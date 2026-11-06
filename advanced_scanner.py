
import re


# ==================================================
# SECURE CODE EXAMPLES
# ==================================================

SQL_SECURE_CODE = """// Example for a SQL client supporting
// parameterized tagged-template queries.

const searchPattern = `%${searchTerm}%`;

const tasks = await sql`
  SELECT id, title, description, status
  FROM public.tasks
  WHERE title ILIKE ${searchPattern}
  ORDER BY created_at DESC
  LIMIT 25
`;

// Verify that your SQL library parameterizes
// expressions inside tagged templates.
"""


XSS_SECURE_CODE = """// React safely escapes text rendered in JSX.
// Use this when comments should contain plain text.

<div className="comment-text">
  {comment.text}
</div>

// If rich HTML is required, sanitize it with
// a trusted, correctly configured HTML sanitizer.
// Do not pass raw user input directly into
// dangerouslySetInnerHTML.
"""


AUTH_SECURE_CODE = """// Example for a Supabase Edge Function.
// Use the public anon/publishable key with
// the caller's authorization header.

const authHeader = req.headers.get("Authorization");

if (!authHeader?.startsWith("Bearer ")) {
  return new Response("Unauthorized", {
    status: 401,
  });
}

const userClient = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_ANON_KEY") ?? "",
  {
    global: {
      headers: {
        Authorization: authHeader,
      },
    },
  }
);

const token = authHeader.slice(7);

const {
  data: { user },
  error: authError,
} = await userClient.auth.getUser(token);

if (authError || !user) {
  return new Response("Unauthorized", {
    status: 401,
  });
}

// Prefer userClient for database operations,
// so the caller's Row Level Security applies.
// For privileged operations, separately verify
// ownership or permission before using a
// service-role client.
"""


AUTHORIZATION_SECURE_CODE = """// Example: verify ownership before updating.
// Assumes user has already been authenticated.

const { data: task, error } = await userClient
  .from("tasks")
  .select("id, owner_id")
  .eq("id", taskId)
  .single();

if (error || !task || task.owner_id !== user.id) {
  return new Response("Forbidden", {
    status: 403,
  });
}

// Perform only an authorized operation.
// Prefer user-scoped access and enforce RLS.
// Adapt owner_id to the actual database schema.
"""


def build_rls_secure_code(
    table_name,
    policy_name,
    operation,
):
    """
    Build an illustrative RLS fix using the
    actual table and policy name.

    The ownership column is a suggested
    assumption, not a verified schema fact.
    """

    table_name = table_name or "public.your_table"
    policy_name = policy_name or "Existing policy"

    escaped_policy = policy_name.replace('"', '""')

    if operation == "SELECT":
        return f"""-- Example: restrict access to owned records.
-- Confirm the actual ownership column first.
-- Review all other policies on this table.

DROP POLICY IF EXISTS "{escaped_policy}"
ON {table_name};

CREATE POLICY "{escaped_policy}"
ON {table_name}
FOR SELECT
TO authenticated
USING (owner_id = (SELECT auth.uid()));

-- Replace owner_id with the correct column.
-- For profiles, the owner column may be id.
-- Do not change intentionally shared access.
"""

    if operation == "UPDATE":
        return f"""-- Example: restrict updates to owned records.
-- Confirm the actual ownership column first.

DROP POLICY IF EXISTS "{escaped_policy}"
ON {table_name};

CREATE POLICY "{escaped_policy}"
ON {table_name}
FOR UPDATE
TO authenticated
USING (owner_id = (SELECT auth.uid()))
WITH CHECK (owner_id = (SELECT auth.uid()));

-- Replace owner_id with the correct column.
-- Review other policies before deployment.
"""

    if operation == "DELETE":
        return f"""-- Example: restrict deletion to owned records.
-- Confirm the actual ownership column first.

DROP POLICY IF EXISTS "{escaped_policy}"
ON {table_name};

CREATE POLICY "{escaped_policy}"
ON {table_name}
FOR DELETE
TO authenticated
USING (owner_id = (SELECT auth.uid()));

-- Replace owner_id with the correct column.
-- Review other policies before deployment.
"""

    return f"""-- The policy applies to {operation} operations
-- on {table_name}.

-- Review its intended permissions before
-- replacing the policy.

-- A FOR ALL policy may need separate SELECT,
-- INSERT, UPDATE, and DELETE policies.
-- Define appropriate USING and WITH CHECK
-- conditions for each permitted operation.

-- Existing policy: {escaped_policy}
"""


# ==================================================
# ADVANCED SECURITY SCANNER
# ==================================================

def advanced_scan(filename, code):
    findings = []
    lines = code.splitlines()

    lower_filename = (
        filename.replace("\\", "/").lower()
    )

    def add_finding(
        name,
        severity,
        line_number,
        description,
        fix,
        code_context=None,
        secure_code="",
    ):
        if not 1 <= line_number <= len(lines):
            return

        start = max(0, line_number - 4)
        end = min(len(lines), line_number + 3)

        if code_context is None:
            code_context = "\n".join(
                f"{i + 1}: {lines[i]}"
                for i in range(start, end)
            )

        findings.append({
            "Vulnerability": name,
            "Severity": severity,
            "File": filename,
            "Line": line_number,
            "Evidence": (
                lines[line_number - 1]
                .strip()[:180]
            ),
            "CodeContext": code_context,
            "Description": description,
            "Fix": fix,
            "SecureCode": secure_code,
            "Detection": "Advanced Static Analysis",
        })

    # ==================================================
    # 1. SUPABASE SERVICE-ROLE CHECKS
    # ==================================================

    if (
        "/supabase/functions/"
        in "/" + lower_filename
        and lower_filename.endswith((".ts", ".tsx"))
    ):
        service_role_lines = [
            number
            for number, line in enumerate(
                lines, start=1
            )
            if "SUPABASE_SERVICE_ROLE_KEY" in line
        ]

        if service_role_lines:
            has_auth_check = bool(
                re.search(
                    r"\bauth\s*\.\s*"
                    r"(?:getUser|getClaims)\s*\(",
                    code,
                )
            )

            has_authorization_check = (
                has_auth_check
                and bool(
                    re.search(
                        r"\b(?:owner_id|created_by|"
                        r"membership|role)\b",
                        code,
                        re.IGNORECASE,
                    )
                )
            )

            if not has_auth_check:
                add_finding(
                    "Potential missing authentication "
                    "in privileged function",
                    "High",
                    service_role_lines[0],
                    "This Supabase Edge Function references "
                    "a service-role key but does not visibly "
                    "validate the caller using auth.getUser() "
                    "or auth.getClaims(). Service-role access "
                    "can bypass Row Level Security. Other "
                    "authentication mechanisms or deployment "
                    "settings may exist, so verify them "
                    "before confirming the vulnerability.",
                    "Validate the caller's JWT and verify "
                    "permission to access the requested "
                    "resource before performing privileged "
                    "operations. Prefer a user-scoped "
                    "Supabase client when possible.",
                    secure_code=AUTH_SECURE_CODE,
                )

            elif not has_authorization_check:
                add_finding(
                    "Potential missing resource authorization",
                    "High",
                    service_role_lines[0],
                    "The function uses privileged database "
                    "access. Caller authentication does not "
                    "automatically establish permission "
                    "to access or modify a specific record. "
                    "The scanner did not recognize a common "
                    "resource-authorization pattern.",
                    "Check record ownership, membership, "
                    "or the caller's permissions before "
                    "performing privileged database "
                    "operations.",
                    secure_code=AUTHORIZATION_SECURE_CODE,
                )

    # ==================================================
    # 2. SUPABASE ROW LEVEL SECURITY CHECKS
    # ==================================================

    if lower_filename.endswith(".sql"):
        policy_pattern = re.compile(
            r"\bCREATE\s+POLICY\b[\s\S]*?;",
            re.IGNORECASE,
        )

        for match in policy_pattern.finditer(code):
            policy = match.group(0)

            broad_access = re.search(
                r"\bUSING\s*\(\s*true\s*\)",
                policy,
                re.IGNORECASE,
            )

            if not broad_access:
                continue

            line_number = (
                code[
                    :match.start()
                    + broad_access.start()
                ].count("\n") + 1
            )

            operation_match = re.search(
                r"\bFOR\s+"
                r"(SELECT|INSERT|UPDATE|DELETE|ALL)\b",
                policy,
                re.IGNORECASE,
            )

            operation = (
                operation_match.group(1).upper()
                if operation_match
                else "ALL"
            )

            role_match = re.search(
                r"\bTO\s+([\w,\s]+?)"
                r"(?=\bUSING\b|\bWITH\s+CHECK\b|;)",
                policy,
                re.IGNORECASE,
            )

            roles = (
                role_match.group(1).strip().lower()
                if role_match
                else "unspecified"
            )

            # Identify the actual table.
            table_match = re.search(
                r"\bON\s+"
                r"((?:\"?[A-Za-z_][\w]*\"?\.)?"
                r"\"?[A-Za-z_][\w]*\"?)",
                policy,
                re.IGNORECASE,
            )

            table_name = (
                table_match.group(1)
                if table_match
                else "public.your_table"
            )

            # Identify the actual policy name.
            name_match = re.search(
                r"\bCREATE\s+POLICY\s+"
                r"(?:\"([^\"]+)\"|([A-Za-z_][\w]*))",
                policy,
                re.IGNORECASE,
            )

            policy_name = (
                (
                    name_match.group(1)
                    or name_match.group(2)
                )
                if name_match
                else "Existing policy"
            )

            if operation == "SELECT":
                severity = "Medium"

                description = (
                    "This SELECT policy uses USING (true), "
                    "allowing all rows to be selected by "
                    "roles covered by the policy, subject "
                    "to other database access controls. "
                    "This may be intentional for shared "
                    "data. Review whether the records "
                    "contain private information."
                )

            elif operation in (
                "UPDATE", "DELETE", "ALL"
            ):
                severity = "High"

                description = (
                    "This policy uses USING (true) for "
                    f"{operation} operations. It does not "
                    "restrict eligible rows by ownership. "
                    "Review the policy's roles and other "
                    "access controls to determine whether "
                    "unauthorized changes are possible."
                )

            else:
                severity = "Medium"

                description = (
                    "This policy uses USING (true). "
                    "Review its command, roles, and "
                    "intended access requirements."
                )

            description += (
                f" Policy operation: {operation}. "
                f"Roles: {roles}. "
                f"Table: {table_name}."
            )

            secure_code = build_rls_secure_code(
                table_name,
                policy_name,
                operation,
            )

            add_finding(
                "Potential overly permissive RLS policy",
                severity,
                line_number,
                description,
                "For private records, restrict access "
                "using auth.uid(), ownership, membership, "
                "or role-based checks. For intentionally "
                "shared records, document the access "
                "requirements and verify other policies.",
                secure_code=secure_code,
            )

    # ==================================================
    # 3. DYNAMIC SQL INJECTION CHECKS
    # ==================================================

    if lower_filename.endswith(
        (".ts", ".tsx", ".js", ".jsx")
    ):
        sql_template_pattern = re.compile(
            r"`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
            r"[^`]*\$\{[^}]+\}[^`]*`",
            re.IGNORECASE | re.DOTALL,
        )

        for match in sql_template_pattern.finditer(code):
            sql_template = match.group(0)

            interpolation = re.search(
                r"\$\{[^}]+\}",
                sql_template,
            )

            if not interpolation:
                continue

            prefix = code[
                max(0, match.start() - 40):
                match.start()
            ]

            parameterized_tag = re.search(
                r"\b(?:sql|Prisma\.sql)\s*$",
                prefix,
                re.IGNORECASE,
            )

            if parameterized_tag:
                continue

            absolute_position = (
                match.start()
                + interpolation.start()
            )

            line_number = (
                code[:absolute_position]
                .count("\n") + 1
            )

            start = max(0, line_number - 5)
            end = min(
                len(lines), line_number + 5
            )

            context = "\n".join(
                f"{i + 1}: {lines[i]}"
                for i in range(start, end)
            )

            nearby_code = code[
                match.end():
                min(
                    len(code),
                    match.end() + 1000,
                )
            ]

            unsafe_execution = bool(
                re.search(
                    r"\b(?:sql\.unsafe|"
                    r"\.query|\.execute|"
                    r"executeRawUnsafe|"
                    r"queryRawUnsafe)\s*\(",
                    nearby_code,
                    re.IGNORECASE,
                )
            )

            if unsafe_execution:
                description = (
                    "A SQL template contains an "
                    "interpolated expression, and a "
                    "potentially unsafe database execution "
                    "method appears nearby. If the "
                    "interpolated value comes from "
                    "untrusted input, SQL injection "
                    "may be possible. Verify the "
                    "data flow and execution call."
                )

            else:
                description = (
                    "A SQL template contains an "
                    "interpolated expression. If "
                    "untrusted input reaches this "
                    "query without parameterization, "
                    "SQL injection may be possible. "
                    "Verify how the query is executed."
                )

            add_finding(
                "Potential SQL injection in dynamic query",
                (
                    "High"
                    if unsafe_execution
                    else "Medium"
                ),
                line_number,
                description,
                "Use parameterized SQL queries or "
                "a database client's safe "
                "parameter-binding API. Avoid "
                "building SQL strings with "
                "untrusted input.",
                code_context=context,
                secure_code=SQL_SECURE_CODE,
            )


    # ==================================================
    # 3B. SQL STRING CONCATENATION CHECKS
    # ==================================================

    if lower_filename.endswith((".ts", ".tsx", ".js", ".jsx")):
        concatenated_query_pattern = re.compile(
            r"""\b(?:const|let|var)\s+(\w+)\s*=\s*
            (?P<expression>
                (?:"[^"\n]*"|\'[^\'\n]*\')
                \s*\+\s*
                [\s\S]*?
            )
            ;""",
            re.IGNORECASE | re.VERBOSE,
        )

        for match in concatenated_query_pattern.finditer(code):
            query_variable = match.group(1)
            expression = match.group("expression")

            if not re.search(
                r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
                expression,
                re.IGNORECASE,
            ):
                continue

            if not re.search(
                r"""\+\s*[A-Za-z_$][\w.$]*(?:\s*\+|\s*$)""",
                expression.strip(),
            ):
                continue

            remaining_code = code[match.end():]

            unsafe_call = re.search(
                r"\bsql\s*\.\s*unsafe\s*\(\s*"
                + re.escape(query_variable)
                + r"\s*[,)]",
                remaining_code,
            )

            if not unsafe_call:
                continue

            line_number = code[:match.start()].count("\n") + 1

            add_finding(
                "Potential SQL injection in concatenated query",
                "High",
                line_number,
                "A SQL statement is assembled using string "
                "concatenation and passed to sql.unsafe(). "
                "If concatenated values come from untrusted "
                "input, SQL injection may be possible.",
                "Use parameterized queries and bind values "
                "instead of concatenating them into SQL.",
                secure_code=SQL_SECURE_CODE,
            )

    # ==================================================
    # 4. REACT CROSS-SITE SCRIPTING CHECKS
    # ==================================================

    if lower_filename.endswith(
        (".tsx", ".jsx")
    ):
        for line_number, line in enumerate(
            lines, start=1
        ):
            if not re.search(
                r"\bdangerouslySetInnerHTML\b",
                line,
            ):
                continue

            # Inspect nearby code for the HTML source.
            start = max(0, line_number - 2)
            end = min(
                len(lines),
                line_number + 5,
            )

            nearby = "\n".join(
                lines[start:end]
            )

            if not re.search(
                r"\b__html\s*:",
                nearby,
            ):
                continue

            # Ignore a clearly static HTML string literal.
            # Dynamic values must still be reviewed.
            html_value = re.search(
                r"\b__html\s*:\s*",
                nearby,
            )

            if html_value:
                remaining = nearby[html_value.end():].lstrip()

                if remaining.startswith(('"', "'")):
                    quote = remaining[0]
                    literal = re.match(
                        r"^" + re.escape(quote)
                        + r"(?:\\.|[^\\"
                        + re.escape(quote)
                        + r"])*"
                        + re.escape(quote),
                        remaining,
                    )

                    if literal:
                        continue

            add_finding(
                "Potential cross-site scripting (XSS)",
                "High",
                line_number,
                "The component uses "
                "dangerouslySetInnerHTML to render HTML. "
                "If the supplied content is untrusted "
                "and has not been sanitized, an attacker "
                "may be able to inject executable HTML "
                "or JavaScript. Verify the source of "
                "the content and any sanitization.",
                "Render untrusted comments as normal "
                "React text. If rich HTML is required, "
                "sanitize it using a trusted HTML "
                "sanitization library before rendering.",
                secure_code=XSS_SECURE_CODE,
            )

    return findings
