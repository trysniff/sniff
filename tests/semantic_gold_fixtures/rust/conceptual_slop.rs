pub fn slop_prepare_payload(user: Option<&str>) -> Option<&str> {
    let payload = if user.is_some() { user } else { None };
    if payload.is_some() {
        payload
    } else {
        payload
    }
}
