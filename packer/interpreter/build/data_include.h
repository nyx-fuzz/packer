
typedef char* t_path;

typedef int t_fd;

typedef struct{ void* data; size_t size; } t_mmap_buffer;

typedef uint32_t d_flags;
typedef uint8_t d_char;
typedef struct {size_t count; d_char* vals; } d_vec_path_string;
typedef uint8_t d_foo_bla;
typedef uint32_t d_foo_fuu;

#pragma pack(1)
typedef struct {
        d_foo_bla bla;
        d_flags flags;
        d_foo_fuu fuu;
} d_foo;