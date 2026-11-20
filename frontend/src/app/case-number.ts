/** A stable public number shared by case links, lists and details. */
export function caseNumber(item: { id: number; case_number?: string | null }): string {
  return item.case_number ?? `INV-${String(item.id).padStart(7, "0")}`;
}
