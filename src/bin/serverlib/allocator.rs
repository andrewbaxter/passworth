use std::alloc::GlobalAlloc;

#[global_allocator]
static A: ZeroizeAllocator = ZeroizeAllocator;

struct ZeroizeAllocator;

unsafe impl GlobalAlloc for ZeroizeAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        return std::alloc::System.alloc(layout);
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        //. unsafe { std::ptr::write_bytes(ptr, 0, layout.size()) };
        std::alloc::System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let new_ptr = GlobalAlloc::realloc(&std::alloc::System, ptr, layout, new_size);

        //. if new_ptr != ptr && !ptr.is_null() && !new_ptr.is_null() { std::ptr::write_bytes(ptr, 0, layout.size()); }
        return new_ptr;
    }
}
