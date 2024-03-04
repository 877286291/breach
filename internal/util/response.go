package util

type Response struct {
	Code    int
	Message string
	Data    interface{}
}

func NewResponse(code int, message string, data interface{}) *Response {
	return &Response{
		Code:    code,
		Message: message,
		Data:    data,
	}
}
func Success(message string, data interface{}) *Response {
	return NewResponse(0, message, data)
}
func Fail(errorMessage string) *Response {
	return NewResponse(-1, errorMessage, nil)

}
