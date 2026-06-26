(() => {
  const escapeHtml = (value) =>
    value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const classify = (raw) => {
    const trimmed = raw.trimStart();
    if (
      trimmed.startsWith("package ") ||
      trimmed.startsWith("func ") ||
      trimmed.startsWith("//") ||
      raw.includes(":=")
    ) {
      return "go";
    }
    if (
      trimmed.startsWith("cd ") ||
      trimmed.startsWith("kubectl ") ||
      trimmed.startsWith("demos/kratix/scripts/")
    ) {
      return "shell";
    }
    if (
      raw.includes("condition.get(") ||
      raw.includes("env_from_configuration(") ||
      raw.includes("f\"") ||
      trimmed.startsWith("for ")
    ) {
      return "python";
    }
    return "yaml";
  };

  const highlightYamlValue = (value) =>
    value
      .replace(/(".*?"|'.*?')/g, '<span class="tok-string">$1</span>')
      .replace(/\b(true|false|null)\b/g, '<span class="tok-value">$1</span>')
      .replace(
        /\b(https?:\/\/[^\s<]+|catalog:\/\/[^\s<]+)\b/g,
        '<span class="tok-string">$1</span>',
      );

  const highlightYaml = (raw) =>
    escapeHtml(raw)
      .split("\n")
      .map((line) => {
        const commentIndex = line.indexOf("#");
        const comment = commentIndex >= 0 ? line.slice(commentIndex) : "";
        let body = commentIndex >= 0 ? line.slice(0, commentIndex) : line;
        body = body.replace(
          /^(\s*(?:-\s*)?)([A-Za-z0-9_.\[\]-]+)(:)/,
          '$1<span class="tok-key">$2</span>$3',
        );
        body = body.replace(/(:\s*)([^<\n]+)/, (_, prefix, value) => prefix + highlightYamlValue(value));
        return body + (comment ? `<span class="tok-comment">${comment}</span>` : "");
      })
      .join("\n");

  const protectTokens = (raw, rules) => {
    const tokens = [];
    let text = raw;
    rules.forEach(([pattern, tokenClass]) => {
      text = text.replace(pattern, (match) => {
        const placeholder = `@@RC_TOKEN_${tokens.length}@@`;
        tokens.push({
          placeholder,
          html: `<span class="${tokenClass}">${match}</span>`,
        });
        return placeholder;
      });
    });
    return {
      text,
      restore: (value) =>
        tokens.reduce(
          (current, token) => current.replaceAll(token.placeholder, token.html),
          value,
        ),
    };
  };

  const highlightGo = (raw) => {
    const protectedTokens = protectTokens(escapeHtml(raw), [
      [/(`[^`]*`|"[^"\n]*")/g, "tok-string"],
      [/(\/\/.*)$/gm, "tok-comment"],
    ]);
    const highlighted = protectedTokens.text
      .replace(
        /\b(package|import|func|type|struct|return|if|else|defer|var|const|nil|for|range)\b/g,
        '<span class="tok-keyword">$1</span>',
      )
      .replace(/\b(string|int|bool|error|map|context|http)\b/g, '<span class="tok-type">$1</span>')
      .replace(/\b([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()/g, '<span class="tok-func">$1</span>');
    return protectedTokens.restore(highlighted);
  };

  const highlightPython = (raw) => {
    const protectedTokens = protectTokens(escapeHtml(raw), [
      [/(".*?"|'.*?')/g, "tok-string"],
      [/(#.*)$/gm, "tok-comment"],
    ]);
    const highlighted = protectedTokens.text
      .replace(
        /\b(for|if|else|elif|return|in|def|class|import|from|try|except|continue|None|True|False)\b/g,
        '<span class="tok-keyword">$1</span>',
      )
      .replace(/\b([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()/g, '<span class="tok-func">$1</span>');
    return protectedTokens.restore(highlighted);
  };

  const highlightShell = (raw) => {
    const protectedTokens = protectTokens(escapeHtml(raw), [
      [/(&lt;[^&]+&gt;)/g, "tok-value"],
      [/(\\\s*)$/gm, "tok-comment"],
    ]);
    const highlighted = protectedTokens.text.replace(
      /^(\s*)([A-Za-z0-9_./-]+)/gm,
      '$1<span class="tok-command">$2</span>',
    );
    return protectedTokens.restore(highlighted);
  };

  const highlighters = {
    go: highlightGo,
    python: highlightPython,
    shell: highlightShell,
    yaml: highlightYaml,
  };

  document.querySelectorAll("pre code").forEach((block) => {
    const raw = block.textContent;
    const language = classify(raw);
    block.classList.add(`language-${language}`);
    block.innerHTML = highlighters[language](raw);
  });
})();
