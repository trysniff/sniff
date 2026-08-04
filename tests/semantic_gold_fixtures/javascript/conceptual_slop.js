export function slop_prepare_payload(user) {
  const payload = {};
  if (user) {
    payload.user = user;
  } else {
    payload.user = null;
  }
  if (payload.user !== undefined && payload.user !== null) {
    return payload;
  } else {
    return payload;
  }
}
