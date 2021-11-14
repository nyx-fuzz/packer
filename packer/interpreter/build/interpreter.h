//ALL OF THIS IS AUTO GENERATED, DO NOT CHANGE. CHANGE interpreter.jinja.h and regenerate!
#ifndef __INTERPRETER__GEN__
#define __INTERPRETER__GEN__

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter" 

#include<stdint.h>
#include<stddef.h>

//includes



#include<stdlib.h>
#include<assert.h>
#define ASSERT(x) assert(x)
#define VM_MALLOC(x) malloc(x)



#define STATIC_ASSERT(cond, desc) _Static_assert(cond, desc)

#define INTERPRETER_CHECKSUM 12399970063951483723ULL




#define OP_PATH 0
#define OP_PATH_SIZE 2

#define OP_OPEN 1
#define OP_OPEN_SIZE 3

#define OP_FD_0 2
#define OP_FD_0_SIZE 2

#define OP_DUP2 3
#define OP_DUP2_SIZE 3

#define OP_MMAP 4
#define OP_MMAP_SIZE 3
#define DATA_MMAP_SIZE 4

#define OP_CLOSE 5
#define OP_CLOSE_SIZE 2

#define OP_READ 6
#define OP_READ_SIZE 2


#include "data_include.h"

typedef struct {
	uint16_t* ops;
	size_t* ops_len;
	size_t ops_i;

	uint8_t* data;
	size_t* data_len;
	size_t data_i;
	uint32_t* instruction_counter;

	
	t_path* t_path_vals;
	t_fd* t_fd_vals;
	t_mmap_buffer* t_mmap_buffer_vals;

} interpreter_t;


#include "bytecode_spec.h"

//=========================
//atomic data type functions
//=========================

d_flags* read_d_flags(interpreter_t* vm){
	ASSERT(vm->data_i + sizeof(d_flags) <= *vm->data_len);
	STATIC_ASSERT(sizeof(d_flags) == 4, "size missmatch in d_flags");
	d_flags* res = (d_flags*)&vm->data[vm->data_i];
	vm->data_i += sizeof(d_flags);
	return res;
}

d_vec_path_string read_d_vec_path_string(interpreter_t* vm){
	d_vec_path_string res = {0};
	ASSERT(vm->data_i+2 <= *vm->data_len);
	uint16_t byte_size = *((uint16_t*)&vm->data[vm->data_i]);
	vm->data_i+=2;
	ASSERT(vm->data_i+byte_size <= *vm->data_len);
	res.count = ((size_t)byte_size)/sizeof(d_char);
	res.vals = (d_char*)&(vm->data[vm->data_i+2]);
	vm->data_i += byte_size;
	
	return res;
}


//=========================
//edge type functions
//=========================

t_path* get_t_path(interpreter_t* vm, uint16_t op_id){
	return &vm->t_path_vals[op_id];
}

t_fd* get_t_fd(interpreter_t* vm, uint16_t op_id){
	return &vm->t_fd_vals[op_id];
}

t_mmap_buffer* get_t_mmap_buffer(interpreter_t* vm, uint16_t op_id){
	return &vm->t_mmap_buffer_vals[op_id];
}


//=========================
//interpreter functions
//=========================

interpreter_t* new_interpreter(){
	interpreter_t* vm = VM_MALLOC(sizeof(interpreter_t));
	vm->ops = 0;
	vm->ops_len = 0;
	vm->data = 0;
	vm->data_len = 0;
	vm->user_data = NULL;


	vm->t_path_vals = VM_MALLOC(sizeof(t_path)*0xffff);
	vm->t_fd_vals = VM_MALLOC(sizeof(t_fd)*0xffff);
	vm->t_mmap_buffer_vals = VM_MALLOC(sizeof(t_mmap_buffer)*0xffff);

	return vm;
}

void init_interpreter(interpreter_t* vm, uint16_t* ops, size_t* ops_len, uint8_t* data, size_t* data_len, uint32_t* instruction_counter){
	vm->ops=ops;
	vm->ops_len=ops_len;
	vm->ops_i = 0;
	vm->data = data;
	vm->data_i = 0;
	vm->data_len=data_len;
	vm->user_data = NULL;
	vm->instruction_counter = instruction_counter;
}

int interpreter_run(interpreter_t* vm) {
	ASSERT(vm->ops && vm->data); //init_interpreter was called previously
	while(vm->ops_i < *(vm->ops_len)) {
		uint16_t op = vm->ops[vm->ops_i];
		*vm->instruction_counter+=1;
		switch(op){
			

			case OP_PATH: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_PATH_SIZE );d_vec_path_string data = read_d_vec_path_string(vm);
				
				handler_path(&data, get_t_path(vm, vm->ops[vm->ops_i+1]));
				vm->ops_i += OP_PATH_SIZE;
				break;
				}
			case OP_OPEN: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_OPEN_SIZE );
				handler_open(get_t_path(vm, vm->ops[vm->ops_i+1]), get_t_fd(vm, vm->ops[vm->ops_i+2]));
				vm->ops_i += OP_OPEN_SIZE;
				break;
				}
			case OP_FD_0: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_FD_0_SIZE );
				handler_fd_0(get_t_fd(vm, vm->ops[vm->ops_i+1]));
				vm->ops_i += OP_FD_0_SIZE;
				break;
				}
			case OP_DUP2: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_DUP2_SIZE );
				handler_dup2(get_t_fd(vm, vm->ops[vm->ops_i+1]), get_t_fd(vm, vm->ops[vm->ops_i+2]));
				vm->ops_i += OP_DUP2_SIZE;
				break;
				}
			case OP_MMAP: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_MMAP_SIZE );d_flags* data = read_d_flags(vm);
				
				handler_mmap(data, get_t_fd(vm, vm->ops[vm->ops_i+1]), get_t_mmap_buffer(vm, vm->ops[vm->ops_i+2]));
				vm->ops_i += OP_MMAP_SIZE;
				break;
				}
			case OP_CLOSE: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_CLOSE_SIZE );
				handler_close(get_t_fd(vm, vm->ops[vm->ops_i+1]));
				vm->ops_i += OP_CLOSE_SIZE;
				break;
				}
			case OP_READ: {
				ASSERT( *vm->ops_len >= vm->ops_i + OP_READ_SIZE );
				handler_read(get_t_fd(vm, vm->ops[vm->ops_i+1]));
				vm->ops_i += OP_READ_SIZE;
				break;
				}
			default:
					ASSERT(0);
		}
	}
	return 0;
}
#pragma GCC diagnostic pop 
#endif