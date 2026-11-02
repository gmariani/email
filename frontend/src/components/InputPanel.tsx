import { useRef, useState, type DragEvent } from 'react';
import { Alert, Button } from 'react-bootstrap';
import { readEmailFile, type LoadedEmail } from '../lib/files';
import sample from '../sample.eml?raw';

/**
 * Where an email comes in: pasted, dropped, picked from disk, or the built-in example.
 * Everything is read in the browser.
 */
export function InputPanel({ initial, error, onAnalyze }: { initial: string; error: string | null; onAnalyze: (email: LoadedEmail) => void }) {
    const [text, setText] = useState(initial);
    const [dragging, setDragging] = useState(false);
    const [fileError, setFileError] = useState<string | null>(null);
    const input = useRef<HTMLInputElement>(null);

    const load = async (file: File | undefined) => {
        if (!file) return;
        setFileError(null);
        try {
            onAnalyze(await readEmailFile(file));
        } catch (e) {
            setFileError(e instanceof Error ? e.message : "Couldn't read that file.");
        }
    };

    const drop = (event: DragEvent) => {
        event.preventDefault();
        setDragging(false);
        const file = event.dataTransfer.files[0];
        if (file) return void load(file);
        const dropped = event.dataTransfer.getData('text/plain');
        if (dropped) onAnalyze({ source: dropped, note: null });
    };

    return (
        <main className="container-xxl bd-gutter mt-4 my-md-5 bd-content">
            <div
                className={`drop-zone ${dragging ? 'drop-zone--active' : ''}`}
                onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={drop}
            >
                <h1 className="display-5 bd-title mb-2">Where did this email come from?</h1>
                <p className="lead text-body-secondary mb-4">
                    Paste the full source of an email, or drop an <code>.eml</code> or Outlook <code>.msg</code> file. You'll see every server it passed through, whether each link was encrypted, its SPF/DKIM/DMARC results, and what each header means.
                </p>

                {(error || fileError) && <Alert variant="warning">{error ?? fileError}</Alert>}

                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        if (text.trim()) onAnalyze({ source: text, note: null });
                    }}
                >
                    <label htmlFor="source" className="visually-hidden">
                        Email source
                    </label>
                    <textarea
                        id="source"
                        className="form-control source-input"
                        rows={14}
                        spellCheck={false}
                        autoFocus
                        placeholder={'Received: from mail.example.com (mail.example.com [192.0.2.10])\n\tby mx.example.org with ESMTPS id 4AbCd…\n…\nFrom: Someone <someone@example.com>\nSubject: …'}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && text.trim()) onAnalyze({ source: text, note: null });
                        }}
                    />
                    <div className="d-flex flex-wrap gap-2 mt-3 align-items-center">
                        <Button type="submit" variant="primary" disabled={!text.trim()}>
                            <i className="bi bi-search me-1" /> Analyze
                        </Button>
                        <Button variant="outline-light" onClick={() => input.current?.click()}>
                            <i className="bi bi-folder2-open me-1" /> Open file…
                        </Button>
                        <Button variant="link" onClick={() => onAnalyze({ source: sample, note: 'This is a made-up example message.' })}>
                            Try an example
                        </Button>
                        <span className="text-body-secondary small ms-auto">
                            <i className="bi bi-shield-lock me-1" />
                            Read in your browser. The email is never uploaded.
                        </span>
                    </div>
                    <input ref={input} type="file" accept=".eml,.msg,.txt,.mbox,message/rfc822" hidden onChange={(e) => void load(e.target.files?.[0])} />
                </form>
            </div>

            <div className="row g-4 mt-4">
                <HowTo title="Gmail" steps="Open the message › ⋮ (More) › Show original › Copy to clipboard, or Download original for an .eml file." />
                <HowTo title="Outlook" steps="Desktop: File › Properties › Internet headers, or drag the message out to save a .msg. Web: ⋯ › View › View message source." />
                <HowTo title="Apple Mail" steps="View › Message › Raw Source (⌥⌘U), or drag the message to the desktop for an .eml file." />
                <HowTo title="Thunderbird" steps="View › Message Source (Ctrl+U), or File › Save As › File for an .eml." />
            </div>
        </main>
    );
}

function HowTo({ title, steps }: { title: string; steps: string }) {
    return (
        <div className="col-md-6 col-lg-3">
            <h3 className="h6">{title}</h3>
            <p className="small text-body-secondary mb-0">{steps}</p>
        </div>
    );
}
