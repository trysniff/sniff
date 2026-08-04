export function slop_prepare_payload(user: string | null): Record<string, string | null> {
  const payload: Record<string, string | null> = {};
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
