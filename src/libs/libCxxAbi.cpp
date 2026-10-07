#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstddef>
#include <cstdint>

// ---------------------------------------------------------------------------
// Itanium C++ ABI RTTI: __dynamic_cast + the __cxxabiv1 class_type_info vtables.
//
// The ShellUI/JSCd daemon imports these from libc/LibcInternal. Without them,
// __dynamic_cast resolved to KytyPS5's unresolved-import stub (returns 0) so
// every polymorphic dynamic_cast<> and base-class exception match produced a
// NULL, and a std::thread worker crashed on the null. This is a standalone
// reimplementation (does not call the type_info virtuals — it walks the RTTI
// records directly) working on guest pointers, which share the host address
// space. Kind is detected by comparing a type_info's vptr against the three
// class_type_info vtables we publish here. See [[shellui-hle-progress]].
// ---------------------------------------------------------------------------

namespace Libs {
namespace CxxAbi {

LIB_VERSION("libc", 1, "libc", 1, 1);

// Itanium RTTI record layouts (standard, fixed by the ABI).
struct TypeInfo {
	const void* vptr;
	const char* name;
};
struct SiTypeInfo {           // __si_class_type_info: single public non-virtual base
	const void*     vptr;
	const char*     name;
	const TypeInfo* base;
};
struct BaseInfo {             // __base_class_type_info
	const TypeInfo* base;
	long            offset_flags;
};
struct VmiTypeInfo {          // __vmi_class_type_info: multiple / virtual / non-public bases
	const void* vptr;
	const char* name;
	unsigned    flags;
	unsigned    base_count;
	BaseInfo    bases[1];      // base_count entries
};

enum : long { kVirtualMask = 0x1, kPublicMask = 0x2, kOffsetShift = 8 };

// Our published class_type_info vtables. The guest stores a type_info's vptr as
// (vtable symbol + 16), i.e. &vtbl[2]; those three addresses are our kind tags.
using VFn = void (*)();
static void KYTY_SYSV_ABI TiDtor(void* /*self*/) {}
static bool KYTY_SYSV_ABI TiIsPointer(const void* /*self*/) { return false; }
static bool KYTY_SYSV_ABI TiIsFunction(const void* /*self*/) { return false; }
static bool KYTY_SYSV_ABI TiStub() { return false; }
// __do_catch / __do_upcast are defined after the walk (below); forward declare.
static bool KYTY_SYSV_ABI TiDoCatchClass(const void* self, const void* thrown, void** obj, unsigned outer);
static bool KYTY_SYSV_ABI TiDoUpcastClass(const void* self, const void* target, void** obj);

// 8 slots each; guest vptr = &vtbl[2].
static const void* g_vtbl_class[10] = {
    nullptr, nullptr, reinterpret_cast<const void*>(TiDtor), reinterpret_cast<const void*>(TiDtor),
    reinterpret_cast<const void*>(TiIsPointer), reinterpret_cast<const void*>(TiIsFunction),
    reinterpret_cast<const void*>(TiDoCatchClass), reinterpret_cast<const void*>(TiDoUpcastClass),
    reinterpret_cast<const void*>(TiStub), reinterpret_cast<const void*>(TiStub)};
static const void* g_vtbl_si[10] = {
    nullptr, nullptr, reinterpret_cast<const void*>(TiDtor), reinterpret_cast<const void*>(TiDtor),
    reinterpret_cast<const void*>(TiIsPointer), reinterpret_cast<const void*>(TiIsFunction),
    reinterpret_cast<const void*>(TiDoCatchClass), reinterpret_cast<const void*>(TiDoUpcastClass),
    reinterpret_cast<const void*>(TiStub), reinterpret_cast<const void*>(TiStub)};
static const void* g_vtbl_vmi[10] = {
    nullptr, nullptr, reinterpret_cast<const void*>(TiDtor), reinterpret_cast<const void*>(TiDtor),
    reinterpret_cast<const void*>(TiIsPointer), reinterpret_cast<const void*>(TiIsFunction),
    reinterpret_cast<const void*>(TiDoCatchClass), reinterpret_cast<const void*>(TiDoUpcastClass),
    reinterpret_cast<const void*>(TiStub), reinterpret_cast<const void*>(TiStub)};

enum class Kind { Leaf, Si, Vmi, Unknown };
static Kind KindOf(const TypeInfo* t) {
	if (t == nullptr) {
		return Kind::Unknown;
	}
	if (t->vptr == &g_vtbl_class[2]) {
		return Kind::Leaf;
	}
	if (t->vptr == &g_vtbl_si[2]) {
		return Kind::Si;
	}
	if (t->vptr == &g_vtbl_vmi[2]) {
		return Kind::Vmi;
	}
	return Kind::Unknown; // treat as leaf (no bases we can see)
}

} // namespace CxxAbi
} // namespace Libs

namespace Libs {
namespace CxxAbi {

// Recursively search a subobject tree rooted at (T, obj) for a public subobject of type `dst`,
// recording its address. Sets `ambiguous` if two distinct public subobjects of `dst` exist.
struct Search {
	const TypeInfo* dst = nullptr;
	const void*     result = nullptr;
	int             public_count = 0;
	bool            ambiguous = false;
};

static void Find(const TypeInfo* T, const char* obj, bool is_public, Search& s) {
	if (T == nullptr) {
		return;
	}
	if (T == s.dst) {
		if (is_public) {
			if (s.result != nullptr && s.result != obj) {
				s.ambiguous = true;
			}
			s.result = obj;
			s.public_count++;
		}
		return; // found the target subobject; do not descend past it
	}
	switch (KindOf(T)) {
		case Kind::Si: {
			const auto* si = reinterpret_cast<const SiTypeInfo*>(T);
			Find(si->base, obj, is_public, s); // single public base at offset 0
			break;
		}
		case Kind::Vmi: {
			const auto* vmi = reinterpret_cast<const VmiTypeInfo*>(T);
			for (unsigned i = 0; i < vmi->base_count; i++) {
				const BaseInfo& b       = vmi->bases[i];
				long            off      = b.offset_flags >> kOffsetShift;
				const bool      base_pub = (b.offset_flags & kPublicMask) != 0;
				const char*     base_obj = nullptr;
				if ((b.offset_flags & kVirtualMask) != 0) {
					// Virtual base: fetch the vbase offset from the object's primary vtable.
					const char* vptr = *reinterpret_cast<const char* const*>(obj);
					off              = *reinterpret_cast<const long*>(vptr + off);
				}
				base_obj = obj + off;
				Find(b.base, base_obj, is_public && base_pub, s);
			}
			break;
		}
		case Kind::Leaf:
		case Kind::Unknown:
		default:
			break; // no visible bases
	}
}

// __dynamic_cast(static_ptr, static_type, dst_type, src2dst_offset)
static void* KYTY_SYSV_ABI DynamicCast(const void* static_ptr, const TypeInfo* static_type,
                                       const TypeInfo* dst_type, std::ptrdiff_t src2dst) {
	(void)static_type;
	(void)src2dst;
	if (static_ptr == nullptr || dst_type == nullptr) {
		return nullptr;
	}
	const auto* const* vt        = *reinterpret_cast<const void* const* const*>(static_ptr);
	const auto          off2top  = reinterpret_cast<const std::ptrdiff_t*>(vt)[-2];
	const auto*         dyn_type = reinterpret_cast<const TypeInfo*>(vt[-1]);
	const char*         dyn_ptr  = reinterpret_cast<const char*>(static_ptr) + off2top;

	Search s;
	s.dst = dst_type;
	Find(dyn_type, dyn_ptr, true, s);
	if (s.result != nullptr && !s.ambiguous) {
		return const_cast<void*>(s.result);
	}
	return nullptr;
}

// type_info::__do_upcast(target, &obj): adjust obj (of this dynamic type) to a `target` base.
static bool KYTY_SYSV_ABI TiDoUpcastClass(const void* self, const void* target, void** obj) {
	if (self == nullptr || obj == nullptr) {
		return false;
	}
	Search s;
	s.dst = reinterpret_cast<const TypeInfo*>(target);
	Find(reinterpret_cast<const TypeInfo*>(self), reinterpret_cast<const char*>(*obj), true, s);
	if (s.result != nullptr && !s.ambiguous) {
		*obj = const_cast<void*>(s.result);
		return true;
	}
	return false;
}

// type_info::__do_catch(thrown, &obj, outer): can a handler of `self` catch a `thrown` object?
static bool KYTY_SYSV_ABI TiDoCatchClass(const void* self, const void* thrown, void** obj, unsigned outer) {
	(void)outer;
	if (self == thrown) {
		return true; // exact match
	}
	// A handler for base `self` catches a thrown derived `thrown`: upcast thrown -> self.
	if (thrown == nullptr || obj == nullptr) {
		return false;
	}
	Search s;
	s.dst = reinterpret_cast<const TypeInfo*>(self);
	Find(reinterpret_cast<const TypeInfo*>(thrown), reinterpret_cast<const char*>(*obj), true, s);
	if (s.result != nullptr && !s.ambiguous) {
		*obj = const_cast<void*>(s.result);
		return true;
	}
	return false;
}

static void KYTY_SYSV_ABI BadCast() {
	PRINT_NAME();
	LOGF("\t [cxxabi] __cxa_bad_cast (ignored offline)\n");
}
static void KYTY_SYSV_ABI BadTypeid() {
	PRINT_NAME();
	LOGF("\t [cxxabi] __cxa_bad_typeid (ignored offline)\n");
}

LIB_DEFINE(InitCxxAbi_1) {
	LIB_OBJECT("byV+FWlAnB4", g_vtbl_class); // _ZTVN10__cxxabiv117__class_type_infoE
	LIB_OBJECT("pZ9WXcClPO8", g_vtbl_si);    // _ZTVN10__cxxabiv120__si_class_type_infoE
	LIB_OBJECT("9ByRMdo7ywg", g_vtbl_vmi);   // _ZTVN10__cxxabiv121__vmi_class_type_infoE
	LIB_FUNC("hMAe+TWS9mQ", DynamicCast);    // __dynamic_cast
	LIB_FUNC("pBxafllkvt0", BadCast);        // __cxa_bad_cast
	LIB_FUNC("xcc6DTcL8QA", BadTypeid);      // __cxa_bad_typeid
}

} // namespace CxxAbi
} // namespace Libs
