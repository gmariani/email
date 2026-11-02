import { boot } from '../api';

/** The site's navbar, in the same style as the Domain Inspector's search bar. */
export function TopBar({ onNew }: { onNew?: () => void }) {
    return (
        <header className="navbar navbar-expand-lg bd-navbar">
            <nav className="container-xxl bd-gutter d-flex align-items-center">
                <a href={boot.base} className="navbar-brand d-flex align-items-center gap-2 text-reset" onClick={(e) => {
                    if (onNew) {
                        e.preventDefault();
                        onNew();
                    }
                }}>
                    <i className="bi bi-envelope-paper" />
                    <span>Email Header Analyzer</span>
                </a>
                {onNew && (
                    <button type="button" className="btn btn-outline-light btn-sm ms-auto" onClick={onNew}>
                        <i className="bi bi-plus-lg me-1" /> Analyze another
                    </button>
                )}
            </nav>
        </header>
    );
}
