import { Alert } from 'react-bootstrap';
import { checkText, type LookalikeFinding, type OddChar } from '../lib/lookalike';
import { HelpButton, Tip } from './ui';

/** Any text from the message: marked up only when it hides look-alike or invisible characters. */
export function Marked({ text }: { text: string }) {
    // Plain ASCII can't hide anything; skip the check for the common case.
    if (/^[\x20-\x7e]*$/.test(text)) return <>{text}</>;
    const { odd } = checkText(text);
    return odd.length ? <Highlighted text={text} odd={odd} /> : <>{text}</>;
}

/** The text with each look-alike or invisible character marked; hover one to see what it really is. */
export function Highlighted({ text, odd }: { text: string; odd: OddChar[] }) {
    const byChar = new Map(odd.map((o) => [o.char, o]));
    return (
        <>
            {[...text].map((c, i) => {
                const o = byChar.get(c);
                if (!o) return c;
                const label = o.looksLike ? `${o.name}, looks like "${o.looksLike}"` : o.name;
                return (
                    <Tip key={i} label={label}>
                        <mark className={`lookalike ${o.kind === 'invisible' ? 'lookalike--invisible' : ''}`}>{o.kind === 'invisible' ? '·' : c}</mark>
                    </Tip>
                );
            })}
        </>
    );
}

export function LookalikeAlert({ findings }: { findings: LookalikeFinding[] }) {
    if (!findings.length) return null;
    return (
        <Alert variant="danger" className="mb-4">
            <div className="d-flex gap-2 align-items-start">
                <i className="bi bi-incognito fs-5" />
                <div className="flex-grow-1">
                    <strong>Disguised text.</strong> Some of this email is written with characters that only look like ordinary letters. Legitimate senders don't do this: it's used to slip past spam filters and to imitate brands and domains.{' '}
                    <HelpButton>Letters from other alphabets (Cyrillic а, Greek ο), "styled" Unicode letters (𝐒, Ｓ) and invisible characters look normal on screen, but to a computer they're different text, so filters looking for "Storage" or "paypal.com" don't match. Punycode domains (xn--…) are how domains with such letters are written.</HelpButton>
                    <dl className="lookalike-list mb-0 mt-2">
                        {findings.map((f) => (
                            <div key={f.where + f.shown}>
                                <dt>{f.where[0].toUpperCase() + f.where.slice(1)}</dt>
                                <dd>
                                    <span className="lookalike-text">
                                        <Highlighted text={f.shown} odd={f.check.odd} />
                                    </span>
                                    {f.punycode && <div className="small">Written as <code>{f.punycode}</code></div>}
                                    {(f.check.mixed || f.check.styled) && (
                                        <div className="small">
                                            Reads as "{f.check.reads.trim()}", but uses {f.check.odd.filter((o) => o.kind !== 'invisible').length} look-alike letter{f.check.odd.length === 1 ? '' : 's'}{' '}
                                            ({[...new Set(f.check.odd.filter((o) => o.kind !== 'invisible').map((o) => (o.kind === 'styled' ? 'styled' : o.name.split(' ')[0])))].join(', ')}). Hover a highlighted letter to see what it really is.
                                        </div>
                                    )}
                                    {f.check.invisible && !f.check.mixed && !f.check.styled && <div className="small">Contains invisible characters (shown as ·).</div>}
                                </dd>
                            </div>
                        ))}
                    </dl>
                </div>
            </div>
        </Alert>
    );
}
