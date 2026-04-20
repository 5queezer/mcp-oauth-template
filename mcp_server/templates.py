"""
HTML templates for OAuth login page.

Self-contained: no external CSS/JS/fonts. Single function `render_login`
returns a full HTML document. All interpolated values are escaped via
html.escape(..., quote=True) so query-string inputs can't break out of
attributes or inject script.
"""

import html

# Only these OAuth params are round-tripped as hidden fields. Anything else in
# the merged credentials dict is dropped so we don't echo attacker-controlled
# fields back into the form (no hidden-field injection).
_ALLOWED_HIDDEN_FIELDS = (
    "response_type",
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "redirect_uri",
    "state",
    "scope",
)

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  background: #0f1115;
  color: #e6e6e6;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
}
.card {
  width: 100%;
  max-width: 380px;
  background: #171a21;
  border: 1px solid #262a33;
  border-radius: 12px;
  padding: 2rem 1.75rem;
  box-shadow: 0 8px 24px rgba(0,0,0,0.35);
}
h1 {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.25rem 0;
  color: #f5f5f5;
}
.subtitle {
  font-size: 0.875rem;
  color: #8a94a6;
  margin: 0 0 1.5rem 0;
}
label {
  display: block;
  font-size: 0.8125rem;
  color: #b4bccb;
  margin-bottom: 0.5rem;
}
input[type="password"] {
  width: 100%;
  padding: 0.625rem 0.75rem;
  background: #0f1115;
  border: 1px solid #2a2f3a;
  border-radius: 6px;
  color: #f5f5f5;
  font-size: 0.9375rem;
  outline: none;
  transition: border-color 0.15s;
}
input[type="password"]:focus { border-color: #4c7dff; }
button {
  width: 100%;
  margin-top: 1.25rem;
  padding: 0.625rem 1rem;
  background: #4c7dff;
  color: #fff;
  border: 0;
  border-radius: 6px;
  font-size: 0.9375rem;
  font-weight: 500;
  cursor: pointer;
}
button:hover { background: #3d6bed; }
.error {
  margin-top: 0.875rem;
  font-size: 0.8125rem;
  color: #ff7070;
  text-align: center;
}
""".strip()


def render_login(*, title: str, params: dict[str, str], error: str | None = None) -> str:
    """
    Render a password login page. All substitutions are HTML-escaped.

    Args:
        title:  Service name shown in the card heading.
        params: Merged request params; only allow-listed OAuth fields are
                rendered as hidden inputs.
        error:  Optional error message to show below the submit button.
    """
    safe_title = html.escape(title, quote=True)
    hidden = []
    for name in _ALLOWED_HIDDEN_FIELDS:
        value = params.get(name)
        if value is None or value == "":
            continue
        hidden.append(
            f'<input type="hidden" name="{html.escape(name, quote=True)}" '
            f'value="{html.escape(str(value), quote=True)}">'
        )
    hidden_html = "\n      ".join(hidden)

    error_html = ""
    if error:
        error_html = f'<div class="error">{html.escape(error, quote=True)}</div>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{safe_title}</title>
  <style>{_CSS}</style>
</head>
<body>
  <main class="card">
    <h1>{safe_title}</h1>
    <p class="subtitle">Enter admin password to authorize</p>
    <form method="post" action="/authorize" autocomplete="off">
      {hidden_html}
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autofocus required autocomplete="off">
      <button type="submit">Authorize</button>
      {error_html}
    </form>
  </main>
</body>
</html>
"""
