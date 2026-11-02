import { Alert } from 'react-bootstrap';
import { CodeBlock, SectionTitle } from '../components/ui';
import type { Analysis } from '../lib/analyze';

export function RawTab({ analysis }: { analysis: Analysis }) {
    const { message } = analysis;
    const headers = message.headers.map((h) => h.raw).join('\n');
    return (
        <>
            {message.warnings.map((w) => (
                <Alert key={w} variant="warning" className="py-2">
                    {w}
                </Alert>
            ))}
            <SectionTitle>Headers</SectionTitle>
            <div className="bd-group row">
                <CodeBlock copy>{headers}</CodeBlock>
            </div>
            {message.hasBody && (
                <>
                    <SectionTitle className="mt-5">Body</SectionTitle>
                    <div className="bd-group row">
                        <CodeBlock copy>{message.body.length > 200_000 ? `${message.body.slice(0, 200_000)}\n… (${message.body.length - 200_000} more characters)` : message.body}</CodeBlock>
                    </div>
                </>
            )}
        </>
    );
}
