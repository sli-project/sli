// Повтор запроса имеет смысл только для временных сбоев. Ответы 4xx (404, 400, 403)
// детерминированы: повторы по умолчанию (3 попытки с нарастающей паузой) лишь
// добавляли секунды к загрузке и множили ошибки сети в консоли.
export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  const status = Number((error as { status?: number } | null)?.status ?? 0);
  if (status >= 400 && status < 500) return false;
  return failureCount < 2;
}
