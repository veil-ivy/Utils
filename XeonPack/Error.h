#ifndef ERROR_H
#define ERROR_H
typedef enum PE_error {
	PE_error_success = 0,
	rdwr_image_failed = -1,
	rdwr_map_failed=-2
};
#define LOG(...) printf(__VA_ARGS__)
#endif