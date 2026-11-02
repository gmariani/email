import { Marked } from '../components/Lookalikes';
import { SpamRules } from '../components/SpamRules';
import { useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';
import { FactList } from '../components/facts';
import { CodeBlock, HelpButton } from '../components/ui';
import type { Analysis } from '../lib/analyze';
import type { ExplainedHeader } from '../lib/explain';

/**
 * Every header in the order it appears in the message (top = added last), each
 * with the group it belongs to, a plain-English reading, and the raw text
 * folded away underneath.
 */
export function HeadersTab({ analysis }: { analysis: Analysis }) {
    const [filter, setFilter] = useState('');
    const [group, setGroup] = useState('');

    const groups = useMemo(() => {
        const counts = new Map<string, number>();
        for (const h of analysis.headers) counts.set(h.group, (counts.get(h.group) ?? 0) + 1);
        return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
    }, [analysis]);

    const unrecognized = analysis.headers.filter((h) => h.unrecognized).length;
    const needle = filter.trim().toLowerCase();
    const rows = analysis.headers.filter(
        (h) =>
            (!group || (group === '__unrecognized' ? h.unrecognized : h.group === group)) &&
            (!needle || h.field.name.toLowerCase().includes(needle) || h.field.decoded.toLowerCase().includes(needle) || (h.summary ?? '').toLowerCase().includes(needle)),
    );

    return (
        <>
            <div className="d-flex flex-wrap gap-3 align-items-center mb-3">
                <Form.Select value={group} onChange={(e) => setGroup(e.target.value)} className="w-auto" aria-label="Group">
                    <option value="">All groups ({analysis.headers.length})</option>
                    {groups.map(([name, count]) => (
                        <option key={name} value={name}>
                            {name} ({count})
                        </option>
                    ))}
                    {unrecognized > 0 && <option value="__unrecognized">Not recognised ({unrecognized})</option>}
                </Form.Select>
                <Form.Control type="search" placeholder="Search headers…" value={filter} onChange={(e) => setFilter(e.target.value)} className="headers-filter" aria-label="Search headers" />
                <span className="text-body-secondary small">
                    {rows.length === analysis.headers.length ? `${rows.length} headers, in message order (top = added last)` : `${rows.length} of ${analysis.headers.length} headers`}
                </span>
            </div>

            <div className="table-responsive">
                <table className="table table-dark table-striped records headers-table">
                    <thead>
                        <tr>
                            <th className="headers-col-name">Header</th>
                            <th className="headers-col-group">Group</th>
                            <th>What it says</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((h) => (
                            <HeaderRow key={h.field.index} header={h} onGroup={setGroup} />
                        ))}
                    </tbody>
                </table>
            </div>
            {!rows.length && <p className="text-body-secondary">No headers match.</p>}
        </>
    );
}

function HeaderRow({ header, onGroup }: { header: ExplainedHeader; onGroup: (group: string) => void }) {
    const { field, info } = header;
    const description = header.unrecognized ? 'Not a header this page recognises: added by some software along the way.' : info?.description;
    return (
        <tr>
            <td className="headers-col-name">
                <code className="header-name">{field.name}</code>
                {(description || header.help || info?.spec) && (
                    <HelpButton>
                        {description}
                        {header.help && <p className="mb-0 mt-2">{header.help}</p>}
                        {info?.spec && <div className="mt-2 text-body-secondary">{info.spec}</div>}
                    </HelpButton>
                )}
            </td>
            <td className="headers-col-group">
                <button type="button" className="btn btn-link btn-sm p-0 text-start" onClick={() => onGroup(header.group)} title="Show only this group">
                    {header.group}
                </button>
            </td>
            <td className="header-row-body">
                {header.summary && <p className="mb-1 fw-semibold text-break"><Marked text={header.summary} /></p>}
                <FactList facts={header.facts} labelCols={4} />
                <SpamRules rules={header.rules} />
                <details className="mt-1">
                    <summary className="small text-body-secondary">Raw header</summary>
                    <CodeBlock copy>{field.raw}</CodeBlock>
                </details>
            </td>
        </tr>
    );
}
