import type { SpamRule } from '../lib/explain/types';
import { HelpButton, Muted } from './ui';

const round = (n: number) => Math.round(n * 1000) / 1000;

/** Spam-filter rules that matched: rule, points, what it means. Same look as the DMARC tag table. */
export function SpamRules({ rules }: { rules: SpamRule[] }) {
    if (!rules.length) return null;
    const scored = rules.some((r) => r.points !== null);
    const total = rules.reduce((sum, r) => sum + (r.points ?? 0), 0);
    return (
        <div className="table-responsive mt-2">
            <table className="table table-dark table-striped records spam-rules mb-0">
                <thead>
                    <tr>
                        <th>Rule</th>
                        {scored && (
                            <th className="text-end">
                                Points{' '}
                                <HelpButton>
                                    Each rule that matches adds points (spammier) or takes them away (more likely legitimate). The message is treated as spam once the total reaches the server's threshold.{' '}
                                    <a href="https://cwiki.apache.org/confluence/spaces/SPAMASSASSIN/pages/119543481/HowScoresAreAssigned" target="_blank" rel="noopener noreferrer">
                                        How SpamAssassin assigns scores
                                    </a>
                                </HelpButton>
                            </th>
                        )}
                        <th>What it means</th>
                    </tr>
                </thead>
                <tbody>
                    {rules.map((rule, i) => (
                        <tr key={`${rule.name}-${i}`}>
                            <th>
                                <code>{rule.name}</code>
                            </th>
                            {scored && <td className={`text-end text-nowrap ${pointsClass(rule.points)}`}>{rule.points === null ? '' : `${rule.points > 0 ? '+' : ''}${rule.points}`}</td>}
                            <td>
                                {rule.meaning ?? <Muted>Not in this page's list: possibly a custom rule added on this server.</Muted>}
                                {rule.url && (
                                    <a href={rule.url} target="_blank" rel="noopener noreferrer" className="ms-2 small text-nowrap" title={`Search the web for ${rule.name}`}>
                                        Search <i className="bi bi-box-arrow-up-right" />
                                    </a>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
                {scored && (
                    <tfoot>
                        <tr>
                            <th>
                                Total <HelpButton>The server's own total can differ slightly (rounding, or rules it doesn't list).</HelpButton>
                            </th>
                            <td className={`text-end fw-semibold ${pointsClass(total)}`}>{round(total)}</td>
                            <td />
                        </tr>
                    </tfoot>
                )}
            </table>
        </div>
    );
}

function pointsClass(points: number | null): string {
    if (points === null) return '';
    if (points >= 1) return 'text-danger';
    if (points > 0.5) return 'text-warning';
    if (points < 0) return 'text-success';
    return 'text-body-secondary';
}
