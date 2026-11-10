import { useMemo, useState } from 'react';
import { Alert, Button, Nav } from 'react-bootstrap';
import { DomainLink, UrlText, VirusTotalLink } from '../components/links';
import { CodeBlock, HelpButton, Muted, SectionTitle } from '../components/ui';
import type { Analysis } from '../lib/analyze';
import { formatBytes } from '../lib/format';
import { decodeTransfer, findLinks, isAttachment, leafParts, type MimePart } from '../lib/mime';

export function ContentTab({ analysis, onOpenAttached }: { analysis: Analysis; onOpenAttached: (source: string) => void }) {
    const root = analysis.mime;
    const links = useMemo(() => (root ? findLinks(root) : []), [root]);
    if (!root) {
        return <p>Only headers were provided, so there's no body to show. Paste or drop the full message to see its parts, attachments and links.</p>;
    }
    const leaves = leafParts(root);
    const attachments = leaves.filter(isAttachment);
    const html = leaves.find((p) => p.type === 'text/html' && p.text !== null && !isAttachment(p));
    const plain = leaves.find((p) => p.type === 'text/plain' && p.text !== null && !isAttachment(p));

    return (
        <>
            <SectionTitle>
                Structure <HelpButton>MIME lets one email carry several parts: a plain-text and an HTML version of the same text, inline images, attachments, even other emails.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                <ul className="mime-tree">
                    <MimeNode part={root} />
                </ul>
            </div>

            <SectionTitle className="mt-5">Attachments</SectionTitle>
            <div className="bd-group row">
                {attachments.length ? (
                    <div className="table-responsive">
                        <table className="table table-dark table-striped records mb-0">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th />
                                </tr>
                            </thead>
                            <tbody>
                                {attachments.map((part) => (
                                    <tr key={part.path}>
                                        <td className="text-break">{part.filename ?? <Muted>(no name)</Muted>}</td>
                                        <td>
                                            <code>{part.type}</code>
                                            {riskyName(part.filename) && <div className="text-danger small">Executable or macro-enabled file type: don't open unless you expected it.</div>}
                                        </td>
                                        <td>{formatBytes(part.size)}</td>
                                        <td className="text-end text-nowrap">
                                            {part.message !== null && (
                                                <Button size="sm" variant="outline-light" className="me-2" onClick={() => onOpenAttached(part.message as string)}>
                                                    Analyze this email
                                                </Button>
                                            )}
                                            <Button size="sm" variant="outline-light" onClick={() => download(part)}>
                                                <i className="bi bi-download" />
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="mb-0">None.</p>
                )}
            </div>

            <SectionTitle className="mt-5">
                Links <HelpButton>Every web link in the message. A link whose visible text shows one address but goes to another is a classic phishing trick (though newsletters do it too, for click tracking). Links wrapped by a protection or tracking service (Barracuda, Microsoft Safe Links, Proofpoint…) show where they redirect to.</HelpButton>
            </SectionTitle>
            <div className="bd-group row">
                {links.length ? (
                    <div className="table-responsive">
                        <table className="table table-dark table-striped records mb-0">
                            <thead>
                                <tr>
                                    <th>Goes to</th>
                                    <th>Shown as</th>
                                </tr>
                            </thead>
                            <tbody>
                                {links.map((link, i) => (
                                    <tr key={i}>
                                        <td className="text-break">
                                            <LinkTarget url={link.url} host={link.host} />
                                            {link.target && (
                                                <div className="link-forward mt-2">
                                                    <div className="small text-body-secondary">
                                                        <i className="bi bi-arrow-return-right me-1" />
                                                        Redirects to
                                                    </div>
                                                    <LinkTarget url={link.target} host={link.targetHost} />
                                                </div>
                                            )}
                                        </td>
                                        <td className="text-break">
                                            {link.text ?? <Muted>(plain-text link)</Muted>}
                                            {link.mismatch && (
                                                <div className="text-warning small">
                                                    <i className="bi bi-exclamation-triangle-fill me-1" />
                                                    The text shows a different site than the link opens.
                                                </div>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="mb-0">No web links.</p>
                )}
            </div>

            {(html || plain) && (
                <>
                    <SectionTitle className="mt-5">Message</SectionTitle>
                    <div className="bd-group row">
                        <Body html={html} plain={plain} />
                    </div>
                </>
            )}
        </>
    );
}

function LinkTarget({ url, host }: { url: string; host: string | null }) {
    return (
        <>
            {host && (
                <div className="d-flex flex-wrap align-items-baseline gap-2">
                    <DomainLink domain={host} />
                    <VirusTotalLink domain={host} />
                    <VirusTotalLink url={url} />
                </div>
            )}
            <UrlText url={url} />
        </>
    );
}

function MimeNode({ part }: { part: MimePart }) {
    return (
        <li>
            <code>{part.type}</code>
            {part.path && <span className="text-body-secondary small ms-2">part {part.path}</span>}
            {part.filename && <span className="ms-2">{part.filename}</span>}
            {!part.children.length && <span className="text-body-secondary small ms-2">{formatBytes(part.size)}{part.encoding !== '7bit' ? ` · ${part.encoding}` : ''}{part.params.charset ? ` · ${part.params.charset}` : ''}</span>}
            {part.children.length > 0 && (
                <ul>
                    {part.children.map((child) => (
                        <MimeNode key={child.path} part={child} />
                    ))}
                </ul>
            )}
        </li>
    );
}

/**
 * The HTML is shown in a sandboxed frame with no scripts and a policy that
 * blocks every remote load, so tracking pixels and remote images never fire.
 */
function Body({ html, plain }: { html: MimePart | undefined; plain: MimePart | undefined }) {
    const [view, setView] = useState<'preview' | 'text' | 'source'>(html ? 'preview' : 'text');
    const srcDoc = useMemo(
        () =>
            html?.text
                ? `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:"><base target="_blank">${html.text}`
                : '',
        [html],
    );
    return (
        <>
            <Nav variant="tabs" activeKey={view} onSelect={(k) => k && setView(k as typeof view)} className="mb-3">
                {html && (
                    <Nav.Item>
                        <Nav.Link eventKey="preview">Preview</Nav.Link>
                    </Nav.Item>
                )}
                {plain && (
                    <Nav.Item>
                        <Nav.Link eventKey="text">Plain text</Nav.Link>
                    </Nav.Item>
                )}
                {html && (
                    <Nav.Item>
                        <Nav.Link eventKey="source">HTML source</Nav.Link>
                    </Nav.Item>
                )}
            </Nav>
            {view === 'preview' && html && (
                <>
                    <Alert variant="secondary" className="py-2 small">
                        Remote images and scripts are blocked, so opening this preview doesn't tell the sender you read it.
                    </Alert>
                    <iframe title="Message preview" className="message-preview" sandbox="allow-popups allow-popups-to-escape-sandbox" srcDoc={srcDoc} />
                </>
            )}
            {view === 'text' && plain?.text && <CodeBlock copy>{plain.text}</CodeBlock>}
            {view === 'source' && html?.text && <CodeBlock copy language="html">{html.text}</CodeBlock>}
        </>
    );
}

const RISKY = /\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|hta|msi|msix|ps1|jar|lnk|iso|img|vhd|docm|xlsm|pptm|xlam|one|html?|svg)$/i;

function riskyName(name: string | null): boolean {
    return !!name && RISKY.test(name.trim());
}

function download(part: MimePart) {
    const bytes = decodeTransfer(part.body, part.encoding);
    const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (part.filename ?? `part-${part.path || 'body'}`).replace(/[\\/:*?"<>|]/g, '_');
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
