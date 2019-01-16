#ifndef LIBDSEBYPASS_H
#define LIBDSEBYPASS_H

typedef void(*KERNEL_EXPL_HANDLER)(void *context);


#ifdef __cplusplus

extern "C"
{

#endif


	bool kernel_expl_load_driver(void *data, unsigned int data_size);


#ifdef __cplusplus

}

#endif
#endif // LIBDSEBYPASS_H