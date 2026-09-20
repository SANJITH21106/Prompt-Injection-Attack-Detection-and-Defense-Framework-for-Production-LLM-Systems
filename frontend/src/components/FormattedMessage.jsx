import React from 'react';

/**
 * Parses inline markdown tokens: **bold**, *italic*, `inline code`.
 */
function renderInline(text) {
  if (!text) return null;
  const parts = [];
  const regex = /(\*\*.*?\*\*|\*[^*]+?\*|`[^`]+?`)/g;
  let lastIdx = 0;
  let match;
  let key = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parts.push(text.substring(lastIdx, match.index));
    }
    const token = match[0];
    if (token.startsWith('**') && token.endsWith('**')) {
      parts.push(<strong key={key++}>{token.slice(2, -2)}</strong>);
    } else if (token.startsWith('`') && token.endsWith('`')) {
      parts.push(<code key={key++} className="inline-code">{token.slice(1, -1)}</code>);
    } else if (token.startsWith('*') && token.endsWith('*')) {
      parts.push(<em key={key++}>{token.slice(1, -1)}</em>);
    } else {
      parts.push(token);
    }
    lastIdx = regex.lastIndex;
  }

  if (lastIdx < text.length) {
    parts.push(text.substring(lastIdx));
  }

  return parts.length > 0 ? parts : text;
}

/**
 * Structured Markdown Parser for Chat Messages.
 * Formats headers, bullet lists, code blocks, dividers, and paragraphs cleanly.
 */
export default function FormattedMessage({ content }) {
  if (!content) return null;

  const lines = content.split('\n');
  const elements = [];
  let currentList = [];
  let inCodeBlock = false;
  let codeBuffer = [];
  let codeLanguage = '';

  const flushList = () => {
    if (currentList.length > 0) {
      elements.push(
        <ul key={`ul-${elements.length}`} className="chat-list">
          {currentList.map((item, idx) => (
            <li key={idx}>{renderInline(item)}</li>
          ))}
        </ul>
      );
      currentList = [];
    }
  };

  const flushCode = () => {
    if (codeBuffer.length > 0) {
      elements.push(
        <pre key={`code-${elements.length}`} className="chat-code-block">
          <code>{codeBuffer.join('\n')}</code>
        </pre>
      );
      codeBuffer = [];
      codeLanguage = '';
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    // Code block toggle
    if (line.startsWith('```')) {
      if (inCodeBlock) {
        flushCode();
        inCodeBlock = false;
      } else {
        flushList();
        inCodeBlock = true;
        codeLanguage = line.slice(3).trim();
      }
      continue;
    }

    if (inCodeBlock) {
      codeBuffer.push(rawLine);
      continue;
    }

    // Empty line
    if (!line) {
      flushList();
      continue;
    }

    // Horizontal Rule
    if (line === '---' || line === '***' || line === '___') {
      flushList();
      elements.push(<hr key={`hr-${elements.length}`} className="chat-divider" />);
      continue;
    }

    // Headings
    if (line.startsWith('#### ')) {
      flushList();
      elements.push(
        <h5 key={`h5-${elements.length}`} className="chat-heading-5">
          {renderInline(line.slice(5))}
        </h5>
      );
      continue;
    }
    if (line.startsWith('### ')) {
      flushList();
      elements.push(
        <h4 key={`h4-${elements.length}`} className="chat-heading-4">
          {renderInline(line.slice(4))}
        </h4>
      );
      continue;
    }
    if (line.startsWith('## ')) {
      flushList();
      elements.push(
        <h3 key={`h3-${elements.length}`} className="chat-heading-3">
          {renderInline(line.slice(3))}
        </h3>
      );
      continue;
    }
    if (line.startsWith('# ')) {
      flushList();
      elements.push(
        <h2 key={`h2-${elements.length}`} className="chat-heading-2">
          {renderInline(line.slice(2))}
        </h2>
      );
      continue;
    }

    // Bullet List items (* or - or +)
    const listMatch = line.match(/^([*+-]|\d+\.)\s+(.+)$/);
    if (listMatch) {
      currentList.push(listMatch[2]);
      continue;
    }

    // Regular paragraph
    flushList();
    elements.push(
      <p key={`p-${elements.length}`} className="chat-paragraph">
        {renderInline(line)}
      </p>
    );
  }

  flushList();
  flushCode();

  return <div className="formatted-message">{elements}</div>;
}
