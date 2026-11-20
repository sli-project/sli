using System.Text;
using System.Text.Json.Nodes;
namespace Sli.Server.Reporting.V2;

public sealed record ReportExport(string Body, long Rows, bool Truncated);
public static class ReportCsv
{
    public static string FromColumns(IEnumerable<JsonObject> columns, IEnumerable<JsonObject> rows)
    {
        var list = columns.ToArray(); var output = new StringBuilder();
        Write(output, list.Select(c => Safe(c.Text("label"))));
        foreach (var row in rows)
            Write(output, list.Select(c =>
            {
                var value = ReportJson.Read(row, c.Text("path", c.Text("key")));
                string text = value is JsonArray a ? string.Join(", ", a.Select(n => n is null ? "None" : CellText(n))) : value is null ? "" : CellText(value);
                if (c["labels"] is JsonObject labels && labels[text] is { } label) text = label.GetValue<string>();
                return Safe(text);
            }));
        return output.ToString();
    }
    private static string CellText(JsonNode node) => node is JsonValue value && value.TryGetValue<bool>(out bool flag) ? flag ? "True" : "False" : node.ToString();
    private static string Safe(string text) => text.Length > 0 && (text[0] is '\t' or '\r' or '\n' || text.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@') ? "'" + text : text;
    internal static string Project(string body, ReportDefinition definition, ReportAccess access)
    {
        var visible = access.VisibleColumns;
        if (visible.Length == definition.Columns.Length) return body;
        var rows = Parse(body); var header = rows.FirstOrDefault() ?? [];
        if (!header.SequenceEqual(definition.Columns.Select(c => c.Text("label")))) throw new ReportRequestException("report_field_categories_not_allowed", 403);
        var indices = definition.Columns.Select((c, i) => (c, i)).Where(p => visible.Contains(p.c)).Select(p => p.i).ToArray();
        var output = new StringBuilder();
        foreach (var row in rows)
        {
            if (indices.Any(i => i >= row.Length)) throw new ReportRequestException("report_field_categories_not_allowed", 403);
            Write(output, indices.Select(i => row[i]));
        }
        return output.ToString();
    }
    private static void Write(StringBuilder output, IEnumerable<string> cells)
    {
        var encoded = cells.Select(c => c.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + c.Replace("\"", "\"\"") + "\"" : c).ToArray();
        // A single empty field must remain a record, rather than a blank line.
        if (encoded.Length == 1 && encoded[0].Length == 0) output.Append("\"\"");
        else output.AppendJoin(",", encoded);
        output.Append("\r\n");
    }
    private static List<string[]> Parse(string body)
    {
        var rows = new List<string[]>(); var row = new List<string>(); var cell = new StringBuilder(); bool quoted = false, any = false;
        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i]; any = true;
            if (c == '"')
            {
                if (quoted && i + 1 < body.Length && body[i + 1] == '"') { cell.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (!quoted && c == ',') { row.Add(cell.ToString()); cell.Clear(); }
            else if (!quoted && c is '\r' or '\n')
            {
                if (c == '\r' && i + 1 < body.Length && body[i + 1] == '\n') i++;
                row.Add(cell.ToString()); rows.Add(row.ToArray()); row.Clear(); cell.Clear(); any = false;
            }
            else cell.Append(c);
        }
        if (quoted) throw new ReportRequestException("report_field_categories_not_allowed", 403);
        if (any) { row.Add(cell.ToString()); rows.Add(row.ToArray()); }
        return rows;
    }
}
