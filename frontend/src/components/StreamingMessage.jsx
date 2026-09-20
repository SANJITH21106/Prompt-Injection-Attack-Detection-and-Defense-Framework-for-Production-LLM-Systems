import React, { useState, useEffect } from 'react';
import FormattedMessage from './FormattedMessage';

export default function StreamingMessage({ content, isNew, onComplete }) {
  const [displayedLength, setDisplayedLength] = useState(isNew ? 0 : content.length);
  const isStreaming = displayedLength < content.length;

  useEffect(() => {
    if (!isNew || displayedLength >= content.length) {
      setDisplayedLength(content.length);
      onComplete?.();
      return;
    }

    // Smooth streaming chunk interval
    const timer = setInterval(() => {
      setDisplayedLength((prev) => {
        const next = prev + Math.max(2, Math.floor(content.length / 80));
        if (next >= content.length) {
          clearInterval(timer);
          onComplete?.();
          return content.length;
        }
        return next;
      });
    }, 15);

    return () => clearInterval(timer);
  }, [content, isNew]);

  const displayedContent = isStreaming ? content.substring(0, displayedLength) : content;

  return (
    <div className="streaming-message-container">
      <FormattedMessage content={displayedContent} />
      {isStreaming && <span className="streaming-cursor">▋</span>}
    </div>
  );
}
