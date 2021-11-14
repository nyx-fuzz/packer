//-------------------------
// Move this file to bytecode_spec.h
// and implemented in user spec part

//includes


/**

typedef char* t_path;

typedef int t_fd;

typedef struct{ void* data; size_t size; } t_mmap_buffer;

**/

void interpreter_user_init(interpreter_t *vm){
}

void interpreter_user_shutdown(interpreter_t *vm){
}


void handler_path( interpreter_t *vm, d_vec_path_string *data_path_string, t_path* output_0){
	}

void handler_open( interpreter_t *vm, t_path* borrow_0, t_fd* output_0){
	}

void handler_fd_0( interpreter_t *vm, t_fd* output_0){
	}

void handler_dup2( interpreter_t *vm, t_fd* borrow_0, t_fd* borrow_1){
	}

void handler_mmap( interpreter_t *vm, d_flags *data_flags, t_fd* borrow_0, t_mmap_buffer* output_0){
	}

void handler_close( interpreter_t *vm, t_fd* input_0){
	}

void handler_read( interpreter_t *vm, t_fd* borrow_0){
	}
