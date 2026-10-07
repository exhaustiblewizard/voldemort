#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/threads.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// libSceJsc  (JavaScriptCore C-API surface) — REAL bridge over QuickJS-ng.
//
// The PRE-HERMES ShellUI daemon ("JSCd", zecoxao/kek dump) runs PLAIN JavaScript
// through the JavaScriptCore C-API (module Jsc_v1, 54 imports). Unlike the retail
// 9.00 daemon (Hermes bytecode), this one can be driven by any JS engine, so we
// back the whole JSC C-API with QuickJS-ng (vendored, linked as kyty_quickjs).
//
// Handle model — JSC hands out pointer-sized opaque refs; QuickJS values are
// 16-byte tagged unions, so every ref is a host-heap BOX around a rooted JSValue:
//   JSContextGroupRef      -> JscGroup*  (owns a JSRuntime)
//   JSGlobalContextRef     -> JscCtx*    (a JSContext + its global object box)
//   JSValueRef/JSObjectRef -> JscVal*    ({JSValue v; JSContext* ctx})
//   JSStringRef            -> JscStr*    (UTF-8 string + refcount; ctx-independent)
//   JSClassRef             -> JscClass*  (QuickJS class id + guest def ptr)
//   JSPropertyNameArrayRef -> JscNames*  (vector<string> + refcount)
// Boxes are leak-tolerant (never freed) so JSC's "unowned until Protect" values
// stay alive for the session — matches how the daemon uses them. See
// [[shellui-hle-progress]].
// ---------------------------------------------------------------------------

#if KYTY_HAS_QUICKJS
extern "C" {
#include "quickjs.h"
}
#else
#error "libSceJsc requires QuickJS (kyty_quickjs). Ensure quickjs-master/ exists and reconfigure."
#endif

namespace Libs {
namespace Jsc {

LIB_VERSION("Jsc", 1, "Jsc", 1, 1);

// JSType (JSValueGetType return values), WebKit JSValueRef.h order.
enum JsType : int { kUndefined = 0, kNull = 1, kBoolean = 2, kNumber = 3, kString = 4, kObject = 5, kSymbol = 6 };

struct JscGroup {
	JSRuntime*       rt = nullptr;
	std::atomic<int> rc {1};
};
struct JscCtx {
	JscGroup*        group  = nullptr;
	JSContext*       ctx    = nullptr;
	void*            global = nullptr; // JscVal* boxing the global object
	std::atomic<int> rc {1};
};
// A rooted QuickJS value; the stored JSValue owns one ref for the box's lifetime.
struct JscVal {
	JSValue    v;
	JSContext* ctx = nullptr;
};
struct JscStr {
	std::string      utf8;
	std::atomic<int> rc {1};
};
struct JscNames {
	std::vector<std::string> names;
	std::atomic<int>         rc {1};
};
struct JscClass {
	std::string      name;
	JSClassID        id  = 0;
	const void*      def = nullptr; // guest JSClassDefinition* (readable)
	std::atomic<int> rc {1};
	std::map<JSRuntime*, JSClassID> runtime_ids;
};

// The JscCtx that owns a JSContext is stashed as its opaque so trampolines can
// recover the JSC-side handle to hand back to guest callbacks.
static JscCtx* CtxOf(JSContext* c) { return static_cast<JscCtx*>(JS_GetContextOpaque(c)); }
static std::atomic<size_t> g_memory_limit {std::numeric_limits<size_t>::max()};
static bool TraceCalls() {
	static const bool enabled = [] { const char* value = std::getenv("KYTY_JSC_TRACE"); return value != nullptr && std::strcmp(value, "1") == 0; }();
	return enabled;
}
static std::atomic<uint64_t> g_trace_calls {0};
static JSContext* Q(void* ctx) {
	if (ctx == nullptr) { return nullptr; }
	auto* c = static_cast<JscCtx*>(ctx)->ctx;
	// Apply process options on the runtime's owning JS thread, including existing contexts.
	JS_SetMemoryLimit(JS_GetRuntime(c), g_memory_limit.load(std::memory_order_relaxed));
	return c;
}

static bool KYTY_SYSV_ABI SetOptions(const char* options) {
	Common::HostCriticalScope host_critical;
	if (options == nullptr) { return false; }
	std::string_view text(options);
	constexpr std::string_view prefix = "gcMaxHeapSize=";
	if (!text.starts_with(prefix)) { return false; }
	text.remove_prefix(prefix.size());
	uint64_t bytes = 0;
	const auto parsed = std::from_chars(text.data(), text.data() + text.size(), bytes);
	if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size() ||
	    bytes > std::numeric_limits<size_t>::max()) { return false; }
	g_memory_limit.store(bytes == 0 ? std::numeric_limits<size_t>::max() : static_cast<size_t>(bytes),
	                     std::memory_order_relaxed);
	LOGF("\t JSSetOptions gcMaxHeapSize=%" PRIu64 "\n", bytes);
	return true;
}

// --- box / unbox ---
static JscVal* BoxOwned(JSContext* c, JSValue v) {
	auto* b = new JscVal();
	b->ctx  = c;
	b->v    = v;
	return b;
}
static JscVal* BoxDup(JSContext* c, JSValueConst v) { return BoxOwned(c, JS_DupValue(c, v)); }
static JSValue Unbox(void* ref) { return (ref != nullptr) ? static_cast<JscVal*>(ref)->v : JS_UNDEFINED; }
static JSValue UnboxDup(JSContext* c, void* ref) { return JS_DupValue(c, Unbox(ref)); }

// --- strings ---
static std::string StrOf(void* string_ref) {
	return (string_ref != nullptr) ? static_cast<JscStr*>(string_ref)->utf8 : std::string();
}
static JscStr* NewStr(std::string s) {
	auto* r = new JscStr();
	r->utf8 = std::move(s);
	return r;
}
static JscStr* ValueToJscStr(JSContext* c, JSValueConst v) {
	size_t      len = 0;
	const char* p   = JS_ToCStringLen(c, &len, v);
	auto*       r   = NewStr(p != nullptr ? std::string(p, len) : std::string());
	if (p != nullptr) {
		JS_FreeCString(c, p);
	}
	return r;
}

// JSC callback ABI the guest implements / expects (SysV, called by us into guest).
using GuestCallAsFunction = void* (KYTY_SYSV_ABI*)(void* ctx, void* function, void* this_object, size_t argc,
                                                   void* const* arguments, void** exception);

// Boxing and argument allocation happen before entering this function. Mono
// may stop a guest callback, but must not stop QuickJS or the host allocator.
template<typename Callback, typename... Args>
static decltype(auto) CallGuest(Callback callback, Args... args) {
	Common::HostCriticalPause pause;
	return callback(args...);
}

// QuickJS -> guest trampoline for JSObjectMakeFunctionWithCallback. Guest fn ptr
// stored split across two uint32 func_data slots.
static JSValue TrampCallAsFunction(JSContext* c, JSValueConst this_val, int argc, JSValueConst* argv, int magic,
                                   JSValue* func_data) {
	(void)magic;
	uint32_t lo = 0;
	uint32_t hi = 0;
	JS_ToUint32(c, &lo, func_data[0]);
	JS_ToUint32(c, &hi, func_data[1]);
	auto guest = reinterpret_cast<GuestCallAsFunction>((static_cast<uint64_t>(hi) << 32) | lo);
	if (guest == nullptr) {
		return JS_UNDEFINED;
	}

	JscCtx*            jc       = CtxOf(c);
	JscVal*            this_box = BoxDup(c, this_val);
	JscVal*            fn_box   = BoxDup(c, JS_UNDEFINED); // `function` arg placeholder
	std::vector<void*> args;
	args.reserve(static_cast<size_t>(argc));
	for (int i = 0; i < argc; i++) {
		args.push_back(BoxDup(c, argv[i]));
	}

	void* exc = nullptr;
	const uint64_t trace = TraceCalls() ? g_trace_calls.fetch_add(1, std::memory_order_relaxed) + 1 : 0;
	if (trace != 0 && trace <= 2000) { LOGF("\t JSC guest enter id=%" PRIu64 " ctx=%p callback=%p argc=%d\n", trace, static_cast<void*>(jc), reinterpret_cast<void*>(guest), argc); }
	void* ret = CallGuest(guest, jc, fn_box, this_box, static_cast<size_t>(argc),
	                  args.empty() ? nullptr : args.data(), &exc);
	if (trace != 0 && trace <= 2000) { LOGF("\t JSC guest leave id=%" PRIu64 " exception=%p\n", trace, exc); }

	if (exc != nullptr) {
		return JS_Throw(c, UnboxDup(c, exc));
	}
	if (ret == nullptr) {
		return JS_UNDEFINED;
	}
	return UnboxDup(c, ret);
}

// Build a QuickJS function value that dispatches to a guest callback pointer.
static JSValue MakeGuestFunction(JSContext* c, void* guest_fn, const char* name) {
	auto    p = reinterpret_cast<uint64_t>(guest_fn);
	JSValue data[2];
	data[0]    = JS_NewUint32(c, static_cast<uint32_t>(p & 0xFFFFFFFFu));
	data[1]    = JS_NewUint32(c, static_cast<uint32_t>(p >> 32));
	JSValue fn = JS_NewCFunctionData(c, TrampCallAsFunction, 0, 0, 2, data);
	JS_FreeValue(c, data[0]);
	JS_FreeValue(c, data[1]);
	if (name != nullptr && name[0] != '\0') {
		JS_DefinePropertyValueStr(c, fn, "name", JS_NewString(c, name), 0);
	}
	return fn;
}

// Install a guest JSClassDefinition's staticFunctions onto `target` (fwd; defined
// with the class section). Used for the global-object class at context creation.
static void InstallClassStatics(JSContext* c, JSValueConst target, void* jsClassRef);
static void InitializeClassObject(JSContext* c, JSValueConst target, void* jsClassRef);

// JavaScriptCore exposes Error.stack as a writable, non-enumerable data
// property. QuickJS's lazy getter is useful for the original backtrace, but
// its string-only setter breaks RN's copying of native error metadata.
static JSValue SetErrorStack(JSContext* c, JSValueConst receiver, int argc, JSValueConst* argv) {
	JSValue value = argc > 0 ? JS_DupValue(c, argv[0]) : JS_UNDEFINED;
	if (JS_DefinePropertyValueStr(c, receiver, "stack", value,
	                              JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE | JS_PROP_THROW) < 0) {
		return JS_EXCEPTION;
	}
	return JS_UNDEFINED;
}

static void InstallErrorStackSemantics(JSContext* c, JSValueConst global) {
	JSValue constructor = JS_GetPropertyStr(c, global, "Error");
	JSValue prototype = JS_GetPropertyStr(c, constructor, "prototype");
	JSAtom atom = JS_NewAtom(c, "stack");
	JSPropertyDescriptor descriptor {};
	const int found = JS_GetOwnProperty(c, &descriptor, prototype, atom);
	EXIT_NOT_IMPLEMENTED(found != 1);
	JSValue setter = JS_NewCFunction(c, SetErrorStack, "set stack", 1);
	const int result = JS_DefinePropertyGetSet(c, prototype, atom,
	                                          JS_DupValue(c, descriptor.getter), setter,
	                                          JS_PROP_CONFIGURABLE);
	JS_FreeValue(c, descriptor.value);
	JS_FreeValue(c, descriptor.getter);
	JS_FreeValue(c, descriptor.setter);
	JS_FreeAtom(c, atom);
	JS_FreeValue(c, prototype);
	JS_FreeValue(c, constructor);
	EXIT_NOT_IMPLEMENTED(result < 0);
}

// === Context group / global context ===
// Every exported entry point protects host execution from Mono's preemptive
// suspension. CallGuest temporarily restores suspension for guest callbacks.
static void* KYTY_SYSV_ABI ContextGroupCreate() {
	Common::HostCriticalScope host_critical;
	auto* g = new JscGroup();
	g->rt   = JS_NewRuntime();
	JS_SetMemoryLimit(g->rt, g_memory_limit.load(std::memory_order_relaxed));
	return g;
}
static void* KYTY_SYSV_ABI ContextGroupRetain(void* group) {
	Common::HostCriticalScope host_critical;
	if (group != nullptr) {
		static_cast<JscGroup*>(group)->rc.fetch_add(1, std::memory_order_relaxed);
	}
	return group;
}
static void KYTY_SYSV_ABI ContextGroupRelease(void* group) {
	Common::HostCriticalScope host_critical;
	if (group != nullptr) {
		static_cast<JscGroup*>(group)->rc.fetch_sub(1, std::memory_order_relaxed);
	}
}
// JSGlobalContextCreateInGroup(JSContextGroupRef group, JSClassRef globalObjectClass)
static void* KYTY_SYSV_ABI GlobalContextCreateInGroup(void* group, void* global_class) {
	Common::HostCriticalScope host_critical;
	PRINT_NAME();
	auto* g   = (group != nullptr) ? static_cast<JscGroup*>(group) : static_cast<JscGroup*>(ContextGroupCreate());
	auto* jc  = new JscCtx();
	jc->group = g;
	jc->ctx   = JS_NewContext(g->rt);
	JS_SetContextOpaque(jc->ctx, jc);
	JSValue global = JS_GetGlobalObject(jc->ctx);
	InstallErrorStackSemantics(jc->ctx, global);
	jc->global     = BoxOwned(jc->ctx, global);
	if (global_class != nullptr) {
		InstallClassStatics(jc->ctx, global, global_class);
	}
	LOGF("\t ctx = %p (group %p, class %p)\n", static_cast<void*>(jc), group, global_class);
	return jc;
}
static void* KYTY_SYSV_ABI GlobalContextRetain(void* ctx) {
	Common::HostCriticalScope host_critical;
	if (ctx != nullptr) {
		static_cast<JscCtx*>(ctx)->rc.fetch_add(1, std::memory_order_relaxed);
	}
	return ctx;
}
static void KYTY_SYSV_ABI GlobalContextRelease(void* ctx) {
	Common::HostCriticalScope host_critical;
	if (ctx != nullptr) {
		static_cast<JscCtx*>(ctx)->rc.fetch_sub(1, std::memory_order_relaxed);
	}
}
static void* KYTY_SYSV_ABI ContextGetGlobalObject(void* ctx) {
	Common::HostCriticalScope host_critical;
	return (ctx != nullptr) ? static_cast<JscCtx*>(ctx)->global : nullptr;
}
static void* KYTY_SYSV_ABI ContextGetGroup(void* ctx) {
	Common::HostCriticalScope host_critical;
	return (ctx != nullptr) ? static_cast<JscCtx*>(ctx)->group : nullptr;
}
static void KYTY_SYSV_ABI GlobalContextSetUnhandledRejectionCallback(void* ctx, void* fn, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)ctx; (void)fn; (void)exc;
}

// === Strings (context-independent UTF-8, refcounted) ===
static void* KYTY_SYSV_ABI StringCreateWithUTF8CString(const char* str) {
	Common::HostCriticalScope host_critical;
	return NewStr(str != nullptr ? std::string(str) : std::string());
}
static void* KYTY_SYSV_ABI StringRetain(void* s) {
	Common::HostCriticalScope host_critical;
	if (s != nullptr) {
		static_cast<JscStr*>(s)->rc.fetch_add(1, std::memory_order_relaxed);
	}
	return s;
}
static void KYTY_SYSV_ABI StringRelease(void* s) {
	Common::HostCriticalScope host_critical;
	if (s != nullptr) {
		static_cast<JscStr*>(s)->rc.fetch_sub(1, std::memory_order_relaxed);
	}
}
static size_t KYTY_SYSV_ABI StringGetMaximumUTF8CStringSize(void* s) {
	Common::HostCriticalScope host_critical;
	return (s != nullptr) ? static_cast<JscStr*>(s)->utf8.size() * 3 + 1 : 1;
}
static size_t KYTY_SYSV_ABI StringGetUTF8CString(void* s, char* buffer, size_t buffer_size) {
	Common::HostCriticalScope host_critical;
	if (buffer == nullptr || buffer_size == 0) {
		return 0;
	}
	const std::string u = StrOf(s);
	const size_t      n = (u.size() + 1 <= buffer_size) ? u.size() : (buffer_size - 1);
	std::memcpy(buffer, u.data(), n);
	buffer[n] = '\0';
	return n + 1; // bytes incl NUL
}
static bool KYTY_SYSV_ABI StringIsEqual(void* a, void* b) {
	Common::HostCriticalScope host_critical;
	if (a == nullptr || b == nullptr) {
		return a == b;
	}
	return static_cast<JscStr*>(a)->utf8 == static_cast<JscStr*>(b)->utf8;
}

// === Value constructors (all take JSContextRef as arg0) ===
static void* KYTY_SYSV_ABI ValueMakeUndefined(void* ctx) {
	Common::HostCriticalScope host_critical; return BoxOwned(Q(ctx), JS_UNDEFINED); }
static void* KYTY_SYSV_ABI ValueMakeNull(void* ctx) {
	Common::HostCriticalScope host_critical; return BoxOwned(Q(ctx), JS_NULL); }
static void* KYTY_SYSV_ABI ValueMakeBoolean(void* ctx, bool b) {
	Common::HostCriticalScope host_critical; return BoxOwned(Q(ctx), JS_NewBool(Q(ctx), b)); }
static void* KYTY_SYSV_ABI ValueMakeNumber(void* ctx, double n) {
	Common::HostCriticalScope host_critical; return BoxOwned(Q(ctx), JS_NewFloat64(Q(ctx), n)); }
static void* KYTY_SYSV_ABI ValueMakeString(void* ctx, void* s) {
	Common::HostCriticalScope host_critical;
	const std::string u = StrOf(s);
	return BoxOwned(Q(ctx), JS_NewStringLen(Q(ctx), u.data(), u.size()));
}
static void* KYTY_SYSV_ABI ValueMakeFromJSONString(void* ctx, void* s) {
	Common::HostCriticalScope host_critical;
	const std::string u = StrOf(s);
	if (std::getenv("KYTY_JSC_TRACE_CONSTANTS") != nullptr) {
		const auto position = u.find("descriptionAnimDur");
		if (position != std::string::npos) {
			const auto part = u.substr(position, 200);
			LOGF("JSC incoming view constants: %s\n", part.c_str());
		}
	}
	JSValue           v = JS_ParseJSON(Q(ctx), u.data(), u.size(), "<json>");
	if (JS_IsException(v)) {
		JS_FreeValue(Q(ctx), v);
		return BoxOwned(Q(ctx), JS_NULL);
	}
	return BoxOwned(Q(ctx), v);
}
// JSValueCreateJSONString(ctx, value, unsigned indent, JSValueRef* exception) -> JSStringRef
static void* KYTY_SYSV_ABI ValueCreateJSONString(void* ctx, void* value, unsigned indent, void** exc) {
	Common::HostCriticalScope host_critical;
	if (exc != nullptr) {
		*exc = nullptr;
	}
	JSContext* c      = Q(ctx);
	JSValue    ind    = (indent != 0) ? JS_NewInt32(c, static_cast<int32_t>(indent)) : JS_UNDEFINED;
	JSValue    result = JS_JSONStringify(c, Unbox(value), JS_UNDEFINED, ind);
	JS_FreeValue(c, ind);
	if (JS_IsException(result)) {
		JSValue e = JS_GetException(c);
		if (exc != nullptr) {
			*exc = BoxOwned(c, e);
		} else {
			JS_FreeValue(c, e);
		}
		JS_FreeValue(c, result);
		return nullptr;
	}
	if (JS_IsUndefined(result)) {
		JS_FreeValue(c, result);
		return nullptr;
	}
	auto* r = ValueToJscStr(c, result);
	JS_FreeValue(c, result);
	return r;
}

// === Value inspection / conversion ===
static int KYTY_SYSV_ABI ValueGetType(void* ctx, void* v) {
	Common::HostCriticalScope host_critical;
	(void)ctx;
	JSValueConst x = Unbox(v);
	if (JS_IsUndefined(x)) return kUndefined;
	if (JS_IsNull(x)) return kNull;
	if (JS_IsBool(x)) return kBoolean;
	if (JS_IsNumber(x)) return kNumber;
	if (JS_IsString(x)) return kString;
	if (JS_IsSymbol(x)) return kSymbol;
	return kObject;
}
static bool KYTY_SYSV_ABI ValueIsUndefined(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsUndefined(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsNull(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsNull(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsBoolean(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsBool(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsNumber(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsNumber(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsString(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsString(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsObject(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; return JS_IsObject(Unbox(v)); }
static bool KYTY_SYSV_ABI ValueIsObjectOfClass(void* ctx, void* v, void* cls) {
	Common::HostCriticalScope host_critical;
	(void)ctx; (void)cls;
	return JS_IsObject(Unbox(v));
}
static bool KYTY_SYSV_ABI ValueIsEqual(void* ctx, void* a, void* b, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	return JS_IsEqual(Q(ctx), Unbox(a), Unbox(b)) > 0;
}
static bool KYTY_SYSV_ABI ValueIsInstanceOfConstructor(void* ctx, void* v, void* ctor, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	return JS_IsInstanceOf(Q(ctx), Unbox(v), Unbox(ctor)) > 0;
}
static bool KYTY_SYSV_ABI ValueToBoolean(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; return JS_ToBool(Q(ctx), Unbox(v)) > 0; }
static double KYTY_SYSV_ABI ValueToNumber(void* ctx, void* v, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	double d = 0.0;
	JS_ToFloat64(Q(ctx), &d, Unbox(v));
	return d;
}
static void* KYTY_SYSV_ABI ValueToStringCopy(void* ctx, void* v, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	return ValueToJscStr(Q(ctx), Unbox(v));
}
static void* KYTY_SYSV_ABI ValueToObject(void* ctx, void* v, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext* c = Q(ctx);
	JSValue    x = Unbox(v);
	if (JS_IsObject(x)) {
		return BoxDup(c, x);
	}
	return BoxOwned(c, JS_NewObject(c));
}
static void KYTY_SYSV_ABI ValueProtect(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; (void)v; } // boxes already rooted
static void KYTY_SYSV_ABI ValueUnprotect(void* ctx, void* v) {
	Common::HostCriticalScope host_critical; (void)ctx; (void)v; }
static int KYTY_SYSV_ABI ValueGetTypedArrayType(void* ctx, void* v, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)ctx; (void)v; (void)exc;
	return 0; // kJSTypedArrayTypeNone
}

// === Objects (a JSObjectRef is a JscVal* whose value is an object) ===
// JSC private data is kept in a side table keyed by object identity, so it works
// for any object regardless of whether it was created with a custom class.
static std::mutex                g_priv_mutex;
static std::map<void*, void*>    g_private; // JS_VALUE_GET_PTR(obj) -> guest data

static void PrivSet(JSValueConst obj, void* data) {
	if (!JS_IsObject(obj)) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_priv_mutex);
	g_private[JS_VALUE_GET_PTR(obj)] = data;
}
static void* PrivGet(JSValueConst obj) {
	if (!JS_IsObject(obj)) {
		return nullptr;
	}
	std::lock_guard<std::mutex> lock(g_priv_mutex);
	auto it = g_private.find(JS_VALUE_GET_PTR(obj));
	return (it != g_private.end()) ? it->second : nullptr;
}

static void* KYTY_SYSV_ABI ObjectMake(void* ctx, void* cls, void* data) {
	Common::HostCriticalScope host_critical;
	JSContext* c = Q(ctx);
	extern JSValue MakeClassObject(JSContext*, JscClass*);
	JSValue o = cls != nullptr ? MakeClassObject(c, static_cast<JscClass*>(cls)) : JS_NewObject(c);
	if (data != nullptr) {
		PrivSet(o, data);
	}
	InstallClassStatics(c, o, cls);
	InitializeClassObject(c, o, cls);
	return BoxOwned(c, o);
}
static void* KYTY_SYSV_ABI ObjectMakeArray(void* ctx, size_t argc, void* const* argv, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext* c   = Q(ctx);
	JSValue    arr = JS_NewArray(c);
	for (size_t i = 0; i < argc && argv != nullptr; i++) {
		JS_SetPropertyUint32(c, arr, static_cast<uint32_t>(i), UnboxDup(c, argv[i]));
	}
	return BoxOwned(c, arr);
}
static void* KYTY_SYSV_ABI ObjectMakeError(void* ctx, size_t argc, void* const* argv, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext* c = Q(ctx);
	JSValue    e = JS_NewError(c);
	if (argc >= 1 && argv != nullptr) {
		JS_SetPropertyStr(c, e, "message", UnboxDup(c, argv[0]));
	}
	return BoxOwned(c, e);
}
static void* KYTY_SYSV_ABI ObjectMakeDate(void* ctx, size_t argc, void* const* argv, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)argc; (void)argv; (void)exc;
	JSContext* c    = Q(ctx);
	JSValue    ctor = JS_GetPropertyStr(c, JS_GetGlobalObject(c), "Date");
	JSValue    d    = JS_CallConstructor(c, ctor, 0, nullptr);
	JS_FreeValue(c, ctor);
	return BoxOwned(c, d);
}
static void* KYTY_SYSV_ABI ObjectMakeFunctionWithCallback(void* ctx, void* name, void* callback) {
	Common::HostCriticalScope host_critical;
	JSContext*  c    = Q(ctx);
	std::string nm   = StrOf(name);
	return BoxOwned(c, MakeGuestFunction(c, callback, nm.c_str()));
}
static bool KYTY_SYSV_ABI ObjectIsFunction(void* ctx, void* object) {
	Common::HostCriticalScope host_critical;
	return JS_IsFunction(Q(ctx), Unbox(object));
}
static bool KYTY_SYSV_ABI ObjectIsConstructor(void* ctx, void* object) {
	Common::HostCriticalScope host_critical;
	return JS_IsConstructor(Q(ctx), Unbox(object));
}
static void* KYTY_SYSV_ABI ObjectGetProperty(void* ctx, void* object, void* prop, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext*  c = Q(ctx);
	std::string p = StrOf(prop);
	return BoxOwned(c, JS_GetPropertyStr(c, Unbox(object), p.c_str()));
}
static void KYTY_SYSV_ABI ObjectSetProperty(void* ctx, void* object, void* prop, void* value, unsigned attrs,
                                            void* exc) {
	Common::HostCriticalScope host_critical;
	(void)attrs; (void)exc;
	JSContext*  c = Q(ctx);
	std::string p = StrOf(prop);
	JS_SetPropertyStr(c, Unbox(object), p.c_str(), UnboxDup(c, value));
}
static bool KYTY_SYSV_ABI ObjectHasProperty(void* ctx, void* object, void* prop) {
	Common::HostCriticalScope host_critical;
	JSContext*  c    = Q(ctx);
	std::string p    = StrOf(prop);
	JSAtom      atom = JS_NewAtom(c, p.c_str());
	int         has  = JS_HasProperty(c, Unbox(object), atom);
	JS_FreeAtom(c, atom);
	return has > 0;
}
static void* KYTY_SYSV_ABI ObjectGetPropertyAtIndex(void* ctx, void* object, unsigned idx, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext* c = Q(ctx);
	return BoxOwned(c, JS_GetPropertyUint32(c, Unbox(object), idx));
}
static void KYTY_SYSV_ABI ObjectSetPropertyAtIndex(void* ctx, void* object, unsigned idx, void* value, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	JSContext* c = Q(ctx);
	JS_SetPropertyUint32(c, Unbox(object), idx, UnboxDup(c, value));
}
static void* KYTY_SYSV_ABI ObjectGetPrivate(void* object) {
	Common::HostCriticalScope host_critical;
	return PrivGet(Unbox(object));
}
static bool KYTY_SYSV_ABI ObjectSetPrivate(void* object, void* data) {
	Common::HostCriticalScope host_critical;
	JSValueConst x = Unbox(object);
	if (JS_IsObject(x)) {
		PrivSet(x, data);
		return true;
	}
	return false;
}
static void* KYTY_SYSV_ABI ObjectGetPrototype(void* ctx, void* object) {
	Common::HostCriticalScope host_critical;
	JSContext* c = Q(ctx);
	return BoxOwned(c, JS_GetPrototype(c, Unbox(object)));
}
static void KYTY_SYSV_ABI ObjectSetPrototype(void* ctx, void* object, void* value) {
	Common::HostCriticalScope host_critical;
	JS_SetPrototype(Q(ctx), Unbox(object), Unbox(value));
}
static void* KYTY_SYSV_ABI ObjectCallAsFunction(void* ctx, void* object, void* this_obj, size_t argc, void* const* argv,
                                                void* exc) {
	Common::HostCriticalScope host_critical;
	JSContext*           c = Q(ctx);
	const uint64_t trace = TraceCalls() ? g_trace_calls.fetch_add(1, std::memory_order_relaxed) + 1 : 0;
	if (trace != 0 && trace <= 2000) { LOGF("\t JSC call enter id=%" PRIu64 " ctx=%p object=%p argc=%zu\n", trace, ctx, object, argc); }
	std::vector<JSValue> a;
	a.reserve(argc);
	for (size_t i = 0; i < argc && argv != nullptr; i++) {
		a.push_back(Unbox(argv[i]));
	}
	JSValue r = JS_Call(c, Unbox(object), Unbox(this_obj), static_cast<int>(argc), a.empty() ? nullptr : a.data());
	if (trace != 0 && trace <= 2000) { LOGF("\t JSC call leave id=%" PRIu64 " exception=%d\n", trace, JS_IsException(r)); }
	if (JS_IsException(r)) {
		JSValue e = JS_GetException(c);
		const char* message = JS_ToCString(c, e);
		LOGF("\t JSC call EXCEPTION: %s\n", message != nullptr ? message : "(unknown)");
		if (message != nullptr) { JS_FreeCString(c, message); }
		if (exc != nullptr) {
			*static_cast<void**>(exc) = BoxOwned(c, e);
		} else {
			JS_FreeValue(c, e);
		}
		JS_FreeValue(c, r);
		return nullptr;
	}
	if (exc != nullptr) {
		*static_cast<void**>(exc) = nullptr;
	}
	return BoxOwned(c, r);
}
static void* KYTY_SYSV_ABI ObjectCallAsConstructor(void* ctx, void* object, size_t argc, void* const* argv,
                                                   void* exc) {
	Common::HostCriticalScope host_critical;
	JSContext*           c = Q(ctx);
	std::vector<JSValue> a;
	a.reserve(argc);
	for (size_t i = 0; i < argc && argv != nullptr; i++) {
		a.push_back(Unbox(argv[i]));
	}
	JSValue r = JS_CallConstructor(c, Unbox(object), static_cast<int>(argc), a.empty() ? nullptr : a.data());
	if (JS_IsException(r)) {
		JSValue e = JS_GetException(c);
		if (exc != nullptr) {
			*static_cast<void**>(exc) = BoxOwned(c, e);
		} else {
			JS_FreeValue(c, e);
		}
		JS_FreeValue(c, r);
		return nullptr;
	}
	if (exc != nullptr) {
		*static_cast<void**>(exc) = nullptr;
	}
	return BoxOwned(c, r);
}
static void* KYTY_SYSV_ABI ObjectGetArrayBufferBytesPtr(void* ctx, void* object, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	size_t len = 0;
	return JS_GetArrayBuffer(Q(ctx), &len, Unbox(object));
}
static size_t KYTY_SYSV_ABI ObjectGetArrayBufferByteLength(void* ctx, void* object, void* exc) {
	Common::HostCriticalScope host_critical;
	(void)exc;
	size_t len = 0;
	JS_GetArrayBuffer(Q(ctx), &len, Unbox(object));
	return len;
}

// === Property name enumeration ===
static void* KYTY_SYSV_ABI ObjectCopyPropertyNames(void* ctx, void* object) {
	Common::HostCriticalScope host_critical;
	JSContext* c   = Q(ctx);
	auto*      arr = new JscNames();
	JSPropertyEnum* tab = nullptr;
	uint32_t        len = 0;
	if (JS_GetOwnPropertyNames(c, &tab, &len, Unbox(object), JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
		for (uint32_t i = 0; i < len; i++) {
			const char* nm = JS_AtomToCString(c, tab[i].atom);
			if (nm != nullptr) {
				arr->names.emplace_back(nm);
				JS_FreeCString(c, nm);
			}
			JS_FreeAtom(c, tab[i].atom);
		}
		js_free(c, tab);
	}
	return arr;
}
static size_t KYTY_SYSV_ABI PropertyNameArrayGetCount(void* arr) {
	Common::HostCriticalScope host_critical;
	return (arr != nullptr) ? static_cast<JscNames*>(arr)->names.size() : 0;
}
static void* KYTY_SYSV_ABI PropertyNameArrayGetNameAtIndex(void* arr, size_t idx) {
	Common::HostCriticalScope host_critical;
	auto* a = static_cast<JscNames*>(arr);
	if (a != nullptr && idx < a->names.size()) {
		return NewStr(a->names[idx]);
	}
	return NewStr(std::string());
}
static void* KYTY_SYSV_ABI PropertyNameArrayRetain(void* arr) {
	Common::HostCriticalScope host_critical;
	if (arr != nullptr) {
		static_cast<JscNames*>(arr)->rc.fetch_add(1, std::memory_order_relaxed);
	}
	return arr;
}
static void KYTY_SYSV_ABI PropertyNameArrayRelease(void* arr) {
	Common::HostCriticalScope host_critical;
	if (arr != nullptr) {
		static_cast<JscNames*>(arr)->rc.fetch_sub(1, std::memory_order_relaxed);
	}
}
static void KYTY_SYSV_ABI PropertyNameAccumulatorAddName(void* acc, void* name) {
	Common::HostCriticalScope host_critical;
	if (acc != nullptr) {
		static_cast<JscNames*>(acc)->names.push_back(StrOf(name));
	}
}

// === Class ===
// Guest JSClassDefinition / JSStaticFunction layout (x64, natural alignment).
#pragma pack(push, 1)
struct GuestStaticFunction {
	uint64_t name;           // const char*
	uint64_t callAsFunction; // JSObjectCallAsFunctionCallback
	uint32_t attributes;
	uint32_t pad;
};
struct GuestClassDefinition {
	int32_t  version;
	uint32_t attributes;
	uint64_t className;       // const char*
	uint64_t parentClass;
	uint64_t staticValues;    // const JSStaticValue*
	uint64_t staticFunctions; // const JSStaticFunction*
	uint64_t initialize;
	uint64_t finalize;
	uint64_t hasProperty;
	uint64_t getProperty;
	uint64_t setProperty;
	uint64_t deleteProperty;
	uint64_t getPropertyNames;
	uint64_t callAsFunction;
	uint64_t callAsConstructor;
	uint64_t hasInstance;
	uint64_t convertToType;
};
#pragma pack(pop)

static void InitializeClassObject(JSContext* c, JSValueConst target, void* jsClassRef) {
	auto* cls = static_cast<JscClass*>(jsClassRef);
	const auto* def = cls != nullptr ? static_cast<const GuestClassDefinition*>(cls->def) : nullptr;
	if (def != nullptr && def->initialize != 0) {
		using Callback = void (KYTY_SYSV_ABI*)(void*, void*);
		CallGuest(reinterpret_cast<Callback>(def->initialize), CtxOf(c), BoxDup(c, target));
	}
}

using GuestGetProperty = void* (KYTY_SYSV_ABI*)(void*, void*, void*, void**);
using GuestSetProperty = bool (KYTY_SYSV_ABI*)(void*, void*, void*, void*, void**);
using GuestGetPropertyNames = void (KYTY_SYSV_ABI*)(void*, void*, void*);

static const GuestClassDefinition* ClassDefinition(JSValueConst obj) {
	auto* cls = static_cast<JscClass*>(JS_GetOpaque(obj, JS_GetClassID(obj)));
	return cls != nullptr ? static_cast<const GuestClassDefinition*>(cls->def) : nullptr;
}

static JscStr* AtomString(JSContext* c, JSAtom atom) {
	const char* name = JS_AtomToCString(c, atom);
	auto* result = NewStr(name != nullptr ? name : "");
	if (name != nullptr) { JS_FreeCString(c, name); }
	return result;
}

static int ClassGetOwnProperty(JSContext* c, JSPropertyDescriptor* desc, JSValueConst obj, JSAtom atom) {
	const auto* def = ClassDefinition(obj);
	if (def == nullptr || def->getProperty == 0) { return 0; }
	void* exception = nullptr;
	void* result = CallGuest(reinterpret_cast<GuestGetProperty>(def->getProperty), CtxOf(c), BoxDup(c, obj), AtomString(c, atom), &exception);
	if (exception != nullptr) { JS_Throw(c, UnboxDup(c, exception)); return -1; }
	// A null JSValueRef asks JSC to continue with ordinary properties/prototypes.
	if (result == nullptr) { return 0; }
	if (desc != nullptr) {
		desc->flags = JS_PROP_C_W_E;
		desc->value = UnboxDup(c, result);
		desc->getter = JS_UNDEFINED;
		desc->setter = JS_UNDEFINED;
	}
	return 1;
}

static int ClassGetOwnPropertyNames(JSContext* c, JSPropertyEnum** table, uint32_t* count, JSValueConst obj) {
	const auto* def = ClassDefinition(obj);
	JscNames names;
	if (def != nullptr && def->getPropertyNames != 0) {
		CallGuest(reinterpret_cast<GuestGetPropertyNames>(def->getPropertyNames), CtxOf(c), BoxDup(c, obj), &names);
	}
	*count = static_cast<uint32_t>(names.names.size());
	*table = static_cast<JSPropertyEnum*>(js_mallocz(c, names.names.size() * sizeof(JSPropertyEnum)));
	if (*count != 0 && *table == nullptr) { return -1; }
	for (uint32_t i = 0; i < *count; ++i) {
		(*table)[i].atom = JS_NewAtom(c, names.names[i].c_str());
		(*table)[i].is_enumerable = true;
	}
	return 0;
}

static int ClassSetProperty(JSContext* c, JSValueConst obj, JSAtom atom, JSValueConst value, JSValueConst, int) {
	const auto* def = ClassDefinition(obj);
	void* exception = nullptr;
	if (def != nullptr && def->setProperty != 0) {
		bool handled = CallGuest(reinterpret_cast<GuestSetProperty>(def->setProperty), CtxOf(c), BoxDup(c, obj), AtomString(c, atom), BoxDup(c, value), &exception);
		if (exception != nullptr) { JS_Throw(c, UnboxDup(c, exception)); return -1; }
		if (handled) { return 1; }
	}
	return JS_DefinePropertyValue(c, obj, atom, JS_DupValue(c, value), JS_PROP_C_W_E);
}

static JSValue ClassCall(JSContext* c, JSValueConst fn, JSValueConst receiver, int argc, JSValueConst* argv, int) {
	const auto* def = ClassDefinition(fn);
	if (def == nullptr || def->callAsFunction == 0) { return JS_ThrowTypeError(c, "Native object is not callable"); }
	std::vector<void*> args;
	for (int i = 0; i < argc; ++i) { args.push_back(BoxDup(c, argv[i])); }
	void* exception = nullptr;
	void* result = CallGuest(reinterpret_cast<GuestCallAsFunction>(def->callAsFunction), CtxOf(c), BoxDup(c, fn), BoxDup(c, receiver), args.size(), args.data(), &exception);
	return exception != nullptr ? JS_Throw(c, UnboxDup(c, exception)) : UnboxDup(c, result);
}

JSValue MakeClassObject(JSContext* c, JscClass* cls) {
	static JSClassExoticMethods exotic = [] {
		JSClassExoticMethods methods {};
		methods.get_own_property = ClassGetOwnProperty;
		methods.get_own_property_names = ClassGetOwnPropertyNames;
		methods.set_property = ClassSetProperty;
		return methods;
	}();
	JSRuntime* runtime = JS_GetRuntime(c);
	auto& id = cls->runtime_ids[runtime];
	const auto* def = static_cast<const GuestClassDefinition*>(cls->def);
	if (id == 0) {
		JS_NewClassID(runtime, &id);
		JSClassDef definition {};
		definition.class_name = cls->name.c_str();
		definition.exotic = &exotic;
		definition.call = def != nullptr && def->callAsFunction != 0 ? ClassCall : nullptr;
		if (JS_NewClass(runtime, id, &definition) < 0) { return JS_EXCEPTION; }
	}
	JSValue obj = JS_NewObjectClass(c, id);
	JS_SetOpaque(obj, cls);
	if (def != nullptr && def->callAsFunction != 0) {
		JSValue global = JS_GetGlobalObject(c);
		JSValue function = JS_GetPropertyStr(c, global, "Function");
		JSValue prototype = JS_GetPropertyStr(c, function, "prototype");
		JS_SetPrototype(c, obj, prototype);
		JS_FreeValue(c, prototype);
		JS_FreeValue(c, function);
		JS_FreeValue(c, global);
	}
	return obj;
}

// Install a class definition's staticFunctions as native methods on `target`.
static void InstallClassStatics(JSContext* c, JSValueConst target, void* jsClassRef) {
	auto* cls = static_cast<JscClass*>(jsClassRef);
	if (cls == nullptr || cls->def == nullptr) {
		return;
	}
	const auto* def = static_cast<const GuestClassDefinition*>(cls->def);
	if (def->staticFunctions == 0) {
		return;
	}
	const auto* fns = reinterpret_cast<const GuestStaticFunction*>(def->staticFunctions);
	for (size_t i = 0; fns[i].name != 0; i++) {
		const char* nm = reinterpret_cast<const char*>(fns[i].name);
		if (fns[i].callAsFunction == 0) {
			continue;
		}
		JSValue fn = MakeGuestFunction(c, reinterpret_cast<void*>(fns[i].callAsFunction), nm);
		JS_SetPropertyStr(c, target, nm, fn);
		LOGF("\t [class %s] static fn %s\n", cls->name.c_str(), nm);
	}
}
static void* KYTY_SYSV_ABI ClassCreate(void* definition) {
	Common::HostCriticalScope host_critical;
	PRINT_NAME();
	auto* cls = new JscClass();
	// JSC copies the definition: libSceJsi builds it on its own stack.
	cls->def = definition != nullptr ? new GuestClassDefinition(*static_cast<const GuestClassDefinition*>(definition)) : nullptr;
	if (definition != nullptr) {
		const auto* def = static_cast<const GuestClassDefinition*>(definition);
		if (def->className != 0) {
			cls->name = reinterpret_cast<const char*>(def->className);
		}
	}
	LOGF("\t class = %s\n", cls->name.c_str());
	return cls;
}
static void* KYTY_SYSV_ABI ClassRetain(void* cls) {
	Common::HostCriticalScope host_critical;
	if (cls != nullptr) {
		static_cast<JscClass*>(cls)->rc.fetch_add(1, std::memory_order_relaxed);
	}
	return cls;
}
static void KYTY_SYSV_ABI ClassRelease(void* cls) {
	Common::HostCriticalScope host_critical;
	if (cls != nullptr) {
		static_cast<JscClass*>(cls)->rc.fetch_sub(1, std::memory_order_relaxed);
	}
}

// === Evaluate — the entry point that actually runs the JS bundle ===
// JSEvaluateScript(ctx, script, thisObject, sourceURL, startingLineNumber, exception)
static void* KYTY_SYSV_ABI EvaluateScript(void* ctx, void* script, void* this_obj, void* source_url, int start_line,
                                          void* exc) {
	Common::HostCriticalScope host_critical;
	PRINT_NAME();
	(void)this_obj; (void)start_line;
	JSContext*        c   = Q(ctx);
	const std::string src = StrOf(script);
	const std::string url = StrOf(source_url);
	LOGF("\t eval %zu bytes, ctx=%p url=%s\n", src.size(), ctx, url.empty() ? "<script>" : url.c_str());
	if (exc != nullptr) {
		*static_cast<void**>(exc) = nullptr;
	}
	JSValue r = JS_Eval(c, src.c_str(), src.size(), url.empty() ? "<script>" : url.c_str(), JS_EVAL_TYPE_GLOBAL);
	if (JS_IsException(r)) {
		JSValue e = JS_GetException(c);
		// Log the message so bundle errors are visible during bring-up.
		const char* msg = JS_ToCString(c, e);
		LOGF("\t eval EXCEPTION: %s\n", msg != nullptr ? msg : "(unknown)");
		if (msg != nullptr) {
			JS_FreeCString(c, msg);
		}
		if (exc != nullptr) {
			*static_cast<void**>(exc) = BoxOwned(c, e);
		} else {
			JS_FreeValue(c, e);
		}
		JS_FreeValue(c, r);
		return nullptr;
	}
	LOGF("\t eval complete %zu bytes, ctx=%p url=%s\n", src.size(), ctx, url.empty() ? "<script>" : url.c_str());
	return BoxOwned(c, r);
}

// === Misc / memory reporting ===
static void KYTY_SYSV_ABI ReportExtraMemoryCost(void* ctx, size_t bytes) {
	Common::HostCriticalScope host_critical; (void)ctx; (void)bytes; }
static void KYTY_SYSV_ABI GetMemoryUsageStatistics(void* ctx, void* out) {
	Common::HostCriticalScope host_critical;
	(void)ctx; (void)out; // struct-out; leave caller's zeroed buffer
}
static void* KYTY_SYSV_ABI ObjectMakeConstructor(void* ctx, void* cls, void* callback) {
	Common::HostCriticalScope host_critical;
	// Construct a plain function acting as constructor; class wiring is minimal.
	JSContext* c = Q(ctx);
	(void)cls;
	return BoxOwned(c, MakeGuestFunction(c, callback, "constructor"));
}
static void* KYTY_SYSV_ABI ObjectMakeTypedArrayWithBytesNoCopy(void* ctx, int array_type, void* bytes,
                                                               size_t byte_length, void* deallocator, void* deallocCtx,
                                                               void* exc) {
	Common::HostCriticalScope host_critical;
	(void)array_type; (void)deallocator; (void)deallocCtx; (void)exc;
	JSContext* c  = Q(ctx);
	JSValue    ab = JS_NewArrayBufferCopy(c, static_cast<const uint8_t*>(bytes), byte_length);
	return BoxOwned(c, ab); // returns an ArrayBuffer; sufficient for byte access offline
}

// @@APPEND@@

LIB_DEFINE(InitJsc_1) {
	LIB_FUNC("vE61ounVJEI", Jsc::SetOptions);
	// Context groups / global context
	LIB_FUNC("kQ0tHfaz-R4", Jsc::GlobalContextCreateInGroup);
	LIB_FUNC("5F4qWfh3NsI", Jsc::GlobalContextRetain);
	LIB_FUNC("b+Bla9TTD04", Jsc::GlobalContextRelease);
	LIB_FUNC("RJW3AojPP1A", Jsc::ContextGetGlobalObject);
	LIB_FUNC("8-gHRL4zbd8", Jsc::GlobalContextSetUnhandledRejectionCallback);
	// Strings
	LIB_FUNC("huNf91I8Tjg", Jsc::StringCreateWithUTF8CString);
	LIB_FUNC("X3L4jbWOtkc", Jsc::StringRetain);
	LIB_FUNC("Nm-U+BAjCkY", Jsc::StringRelease);
	LIB_FUNC("DGkUQEbknmA", Jsc::StringGetMaximumUTF8CStringSize);
	LIB_FUNC("NqV8ddwLaiY", Jsc::StringGetUTF8CString);
	LIB_FUNC("UxDr1iQixuQ", Jsc::StringIsEqual);
	// Value constructors
	LIB_FUNC("mtbYjAKi5NQ", Jsc::ValueMakeUndefined);
	LIB_FUNC("ZSHf8kyWYD4", Jsc::ValueMakeNull);
	LIB_FUNC("YCOZ80HgcTQ", Jsc::ValueMakeBoolean);
	LIB_FUNC("cT71x7KleG0", Jsc::ValueMakeNumber);
	LIB_FUNC("0earDv9xPN8", Jsc::ValueMakeString);
	LIB_FUNC("HR0Ks7kSkUY", Jsc::ValueMakeFromJSONString);
	LIB_FUNC("HRuqgFnBD60", Jsc::ValueCreateJSONString);
	// Value inspection / conversion
	LIB_FUNC("g8-wnopz0jE", Jsc::ValueGetType);
	LIB_FUNC("X+BrzKqtupE", Jsc::ValueIsNull);
	LIB_FUNC("71B6E4fG+sA", Jsc::ValueIsNumber);
	LIB_FUNC("BZx2PqN5SsE", Jsc::ValueIsUndefined);
	LIB_FUNC("Ik7a6r6a7iw", Jsc::ValueIsString);
	LIB_FUNC("tvhjgR5-DlE", Jsc::ValueIsBoolean);
	LIB_FUNC("jn+QXnoXVnc", Jsc::ValueIsObject);
	LIB_FUNC("uDNVMv6AgrQ", Jsc::ValueIsObjectOfClass);
	LIB_FUNC("w3d6oZK52-I", Jsc::ValueIsEqual);
	LIB_FUNC("UPiqgAaHdtU", Jsc::ValueIsInstanceOfConstructor);
	LIB_FUNC("bW+iY4EnrNY", Jsc::ValueToBoolean);
	LIB_FUNC("rSsusHq9Y4Y", Jsc::ValueToNumber);
	LIB_FUNC("9bSDYmkp-Vw", Jsc::ValueToStringCopy);
	LIB_FUNC("qma2Q24pDPI", Jsc::ValueToObject);
	LIB_FUNC("LPpUAOnfyxg", Jsc::ValueProtect);
	LIB_FUNC("ZnucTodXqc0", Jsc::ValueUnprotect);
	LIB_FUNC("49GAz4KpvyA", Jsc::ValueGetTypedArrayType);
	// Objects
	LIB_FUNC("vtHRQyWv+sw", Jsc::ObjectMake);
	LIB_FUNC("o3bxF-l3DoQ", Jsc::ObjectMakeArray);
	LIB_FUNC("96QQlI4MnJw", Jsc::ObjectMakeArray); // nidf-hashed alias touched during setup
	LIB_FUNC("JdoZDRANNUE", Jsc::ObjectMakeError);
	LIB_FUNC("GxotrjFiHnc", Jsc::ObjectMakeConstructor);
	LIB_FUNC("cfJhLH8uj4k", Jsc::ObjectMakeDate);
	LIB_FUNC("94NTgVHUaE8", Jsc::ObjectMakeTypedArrayWithBytesNoCopy);
	LIB_FUNC("Tm9bXhmwlMA", Jsc::ObjectMakeFunctionWithCallback);
	LIB_FUNC("gcsP-2FEZIk", Jsc::ObjectIsFunction);
	LIB_FUNC("pNliRQzOktU", Jsc::ObjectGetProperty);
	LIB_FUNC("z3qLvuQ6R8w", Jsc::ObjectSetProperty);
	LIB_FUNC("35hf1B8ev14", Jsc::ObjectHasProperty);
	LIB_FUNC("lOYH420riKo", Jsc::ObjectGetPropertyAtIndex);
	LIB_FUNC("tr1Uc33FqHY", Jsc::ObjectSetPropertyAtIndex);
	LIB_FUNC("MH3ye94AkZc", Jsc::ObjectGetPrivate);
	LIB_FUNC("+qsTbJFS86A", Jsc::ObjectSetPrivate);
	LIB_FUNC("ytHFpyVl7gw", Jsc::ObjectGetPrototype);
	LIB_FUNC("rp9ESANSaSs", Jsc::ObjectSetPrototype);
	LIB_FUNC("lgC8W0Qu1iw", Jsc::ObjectCallAsFunction);
	LIB_FUNC("f9xif4l1ZhU", Jsc::ObjectCallAsConstructor);
	LIB_FUNC("FEU0ygVamU4", Jsc::ObjectGetArrayBufferBytesPtr);
	LIB_FUNC("uAyWBZtHkgM", Jsc::ObjectGetArrayBufferByteLength);
	// Property name enumeration
	LIB_FUNC("Lcwli-n-8mE", Jsc::ObjectCopyPropertyNames);
	LIB_FUNC("gFwrGZX2VHg", Jsc::PropertyNameArrayGetCount);
	LIB_FUNC("AbA05b6nRfY", Jsc::PropertyNameArrayGetNameAtIndex);
	LIB_FUNC("hR4Q4+3Kw10", Jsc::PropertyNameArrayRelease);
	LIB_FUNC("pw+zuLAiI3U", Jsc::PropertyNameAccumulatorAddName);
	// Class / evaluate / memory
	LIB_FUNC("DSTJsRjpDeg", Jsc::ClassCreate);
	LIB_FUNC("TyyaYni97vQ", Jsc::ClassRelease);
	LIB_FUNC("YssF41MWxCU", Jsc::EvaluateScript);
	LIB_FUNC("gaxkMFwAeDg", Jsc::ReportExtraMemoryCost);
	LIB_FUNC("cjk-Cdurz2c", Jsc::GetMemoryUsageStatistics);

#if KYTY_HAS_QUICKJS
	{
		JSRuntime* rt  = JS_NewRuntime();
		JSContext* ctx = JS_NewContext(rt);
		JSValue    v   = JS_Eval(ctx, "1+2*3", 5, "<smoke>", JS_EVAL_TYPE_GLOBAL);
		int32_t    out = -1;
		JS_ToInt32(ctx, &out, v);
		JS_FreeValue(ctx, v);
		LOGF("\t [QuickJS] smoke test 1+2*3 = %d\n", out);
		JS_FreeContext(ctx);
		JS_FreeRuntime(rt);
	}
#endif
}

} // namespace Jsc
} // namespace Libs
