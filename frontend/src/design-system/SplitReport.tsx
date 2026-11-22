import { useEffect, useId, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Button } from "./Primitives";
import "./split-report.css";

export function SplitReport({ list, title, children, onClose, resizeLabel, expandLabel, restoreLabel, closeLabel }: {
  list: ReactNode;
  title?: string;
  children?: ReactNode;
  onClose: () => void;
  resizeLabel: string;
  expandLabel: string;
  restoreLabel: string;
  closeLabel: string;
}) {
  const [full, setFull] = useState(false);
  const [ratio, setRatio] = useState<number>();
  const [measuredRatio, setMeasuredRatio] = useState(38);
  const region = useRef<HTMLDivElement>(null);
  const listPanel = useRef<HTMLElement>(null);
  const drag = useRef<{ y: number; ratio: number } | null>(null);
  const heading = useId();
  const listId = useId();
  const clamp = (value: number) => Math.min(70, Math.max(18, value));
  const currentRatio = ratio ?? measuredRatio;
  const open = title !== undefined;
  useEffect(() => {
    const list = listPanel.current;
    const split = region.current;
    if (!list || !split || !open || full || ratio !== undefined || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      if (split.clientHeight) setMeasuredRatio(clamp(Math.round(list.offsetHeight / split.clientHeight * 100)));
    };
    const observer = new ResizeObserver(measure);
    observer.observe(list);
    observer.observe(split);
    return () => observer.disconnect();
  }, [open, full, ratio]);

  return <div ref={region} className="sli-ds-split-report" data-open={open}
    style={ratio === undefined ? undefined : { "--sli-split-report-ratio": `${ratio}%` } as CSSProperties}>
    <section ref={listPanel} id={listId} className="sli-ds-split-report__list" hidden={full}>{list}</section>
    {open && !full ? <div className="sli-ds-split-report__handle" tabIndex={0} role="separator"
      aria-label={resizeLabel} aria-orientation="horizontal" aria-controls={listId} aria-valuemin={18} aria-valuemax={70} aria-valuenow={currentRatio}
      onPointerDown={(event) => {
        if (event.button !== 0) return;
        drag.current = { y: event.clientY, ratio: currentRatio };
        event.currentTarget.setPointerCapture(event.pointerId);
      }}
      onPointerMove={(event) => {
        const height = region.current?.clientHeight;
        if (drag.current && height) setRatio(clamp(Math.round(drag.current.ratio + (event.clientY - drag.current.y) / height * 100)));
      }}
      onLostPointerCapture={() => { drag.current = null; }}
      onKeyDown={(event) => {
        const value = { ArrowUp: currentRatio - 3, ArrowDown: currentRatio + 3, Home: 18, End: 70 }[event.key];
        if (value === undefined) return;
        event.preventDefault();
        setRatio(clamp(value));
      }}><span/></div> : null}
    {title !== undefined ? <section className="sli-ds-split-report__card" aria-labelledby={heading}>
      <div className="sli-ds-split-report__heading">
        <h2 id={heading}>{title}</h2>
        <div className="sli-ds-header__actions">
          <Button onClick={() => setFull(!full)}>{full ? restoreLabel : expandLabel}</Button>
          <Button icon="close" aria-label={closeLabel} title={closeLabel} onClick={() => { setFull(false); onClose(); }}/>
        </div>
      </div>
      {children}
    </section> : null}
  </div>;
}
