from .models import User


def convert_serializer_errors_from_dict_to_list(input_dict: dict) -> list:
    serializer_error_arr = []
    for k, v in input_dict.items():
        serializer_error_arr.append(f"{k}: {v[0]}")
    return serializer_error_arr


def get_specific_user_with_email(email: str) -> dict:
    try:
        get_user: User = User.objects.get(email=email)
        return {
            "status": True,
            "response": get_user
        }
    except User.DoesNotExist:
        return {
            "status": False,
            "response": f"user with email: {email} does not exists"
        }


def check_fields_required(input_dict: dict) -> dict:
    for key, value in input_dict.items():
        if not value:
            return {
                "status": False,
                "response": f"{key} is required"
            }
    return {
        "status": True,
        "response": "all fields are present"
    }


def convert_to_error_message(message: any) -> dict:
    return {
        "status": "failure",
        "message": message,
        "data": "null",
    }


def convert_to_success_message_serialized_data(serialized_data: dict) -> dict:
    return {
        "status": "success",
        "message": "request successful",
        "data": serialized_data,
    }


def convert_success_message(message: str) -> dict:
    return {
        "status": "success",
        "message": message,
        "data": "null"
    }
