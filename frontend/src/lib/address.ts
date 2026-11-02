import { splitTopLevel, stripComments } from './message';

export interface Mailbox {
    name: string | null;
    address: string;
    /** Lower-cased domain part, null for a bare local name. */
    domain: string | null;
}

/**
 * Parses an address list such as
 *   "Jane Doe" <jane@example.com>, bob@example.org (Bob), Team: a@x.com, b@y.com;
 * Groups are flattened; "undisclosed-recipients:;" yields nothing.
 */
export function parseAddressList(value: string): Mailbox[] {
    const out: Mailbox[] = [];
    for (let part of splitTopLevel(value, ',')) {
        // "Group name: first@x" — drop the group label (a colon before any "<" or "@"); ";" closes the group.
        const group = /^\s*(?:"[^"]*"|[^"<>@:])*:/.exec(part);
        if (group) part = part.slice(group[0].length);
        part = part.replace(/;\s*$/, '');
        const mailbox = parseMailbox(part);
        if (mailbox) out.push(mailbox);
    }
    return out;
}

export function parseMailbox(value: string): Mailbox | null {
    const angle = /<([^<>]*)>/.exec(value);
    let address: string;
    let name: string | null;
    if (angle) {
        address = angle[1].trim();
        name = unquote(stripComments(value.slice(0, angle.index)).text.trim()) || null;
    } else {
        const { text, comments } = stripComments(value);
        address = text.trim();
        name = comments.find(Boolean) ?? null;
    }
    // Source routes ("@a,@b:user@c") are obsolete; keep the final address.
    address = address.replace(/^(@[^:]+:)/, '').replace(/^mailto:/i, '');
    if (!address && !name) return null;
    const at = address.lastIndexOf('@');
    return { name, address, domain: at > 0 ? address.slice(at + 1).toLowerCase().replace(/\.$/, '') : null };
}

function unquote(text: string): string {
    if (text.startsWith('"') && text.endsWith('"') && text.length >= 2) {
        return text.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    return text;
}

export function formatMailbox(mailbox: Mailbox): string {
    return mailbox.name ? `${mailbox.name} <${mailbox.address}>` : mailbox.address;
}

/** Domain of an address-like string: "<bounce@mail.example.com>" => "mail.example.com" */
export function domainOf(address: string | null | undefined): string | null {
    if (!address) return null;
    const match = /@([^@\s>]+)>?\s*$/.exec(address.trim());
    return match ? match[1].toLowerCase().replace(/\.$/, '') : null;
}
