public enum TraceModel {
    public static func functionName(_ function: UInt32) -> String {
        switch function {
        case 1: "xpc_connection_create"
        case 2: "xpc_pipe_routine"
        case 3: "xpc_connection_send_message"
        case 4: "xpc_connection_send_message_with_reply"
        case 5: "xpc_connection_send_message_with_reply_sync"
        case 6: "_xpc_connection_call_event_handler"
        case 7: "_xpc_connection_check_in"
        case 8: "xpc_dictionary_send_reply"
        case 9: "xpc_session_send_message"
        case 10: "xpc_session_send_message_with_reply_async"
        case 11: "xpc_session_send_message_with_reply_sync"
        case 12: "xpc_connection_create_mach_service"
        case 13: "xpc_connection_create_from_endpoint"
        case 14: "xpc_array_create_connection"
        case 15: "xpc_dictionary_create_connection"
        case 16: "xpc_session_create_xpc_service"
        case 17: "xpc_session_create_mach_service"
        case 18: "xpc_connection_activate"
        case 19: "xpc_connection_resume"
        case 20: "xpc_connection_cancel"
        case 21: "xpc_session_activate"
        case 22: "xpc_session_cancel"
        default: "xpc_function_\(function)"
        }
    }

    public static func role(function: UInt32, direction: TraceDirection, api: TraceAPI) -> TraceRole {
        guard api == .xpc else {
            return api == .diagnostic ? .diagnostic : .mach
        }
        switch function {
        case 2, 4, 5, 10, 11:
            return direction == .entry ? .request : .response
        case 8:
            return .response
        case 6:
            return .incoming
        case 3, 9:
            return .oneWay
        default:
            return .metadata
        }
    }
}
