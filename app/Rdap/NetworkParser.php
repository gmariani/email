<?php

declare(strict_types=1);

namespace EmailReader\Rdap;

/**
 * Reads an RDAP IP network record (inetnum / NetRange) into who owns the
 * network and where its abuse reports go.
 */
final class NetworkParser
{
    /**
     * @param array<string,mixed> $data
     * @return array{registry:?string,url:?string,handle:?string,name:?string,country:?string,range:?string,cidrs:list<string>,organization:?string,abuseEmail:?string,abusePhone:?string}
     */
    public static function parse(array $data, ?string $url): array
    {
        $entities = $data['entities'] ?? [];
        $org = self::entitiesWithRole($entities, 'registrant')[0]
            ?? self::entitiesWithRole($entities, 'administrative')[0]
            ?? ($entities[0] ?? null);
        $orgCard = $org ? self::vcard($org) : [];
        $abuse = self::entitiesWithRole($entities, 'abuse')[0] ?? null;
        $abuseCard = $abuse ? self::vcard($abuse) : [];

        $cidrs = [];
        foreach ($data['cidr0_cidrs'] ?? [] as $cidr) {
            $prefix = $cidr['v4prefix'] ?? $cidr['v6prefix'] ?? null;
            if ($prefix !== null) {
                $cidrs[] = $prefix . '/' . ($cidr['length'] ?? '?');
            }
        }
        $start = $data['startAddress'] ?? null;
        $end = $data['endAddress'] ?? null;

        return [
            'registry' => self::registryName($url),
            'url' => $url,
            'handle' => $data['handle'] ?? null,
            'name' => $data['name'] ?? null,
            'country' => $data['country'] ?? ($orgCard['country'] ?? null),
            'range' => $start && $end ? "{$start} – {$end}" : null,
            'cidrs' => $cidrs,
            'organization' => $orgCard['org'] ?? $orgCard['name'] ?? null,
            'abuseEmail' => $abuseCard['email'] ?? null,
            'abusePhone' => $abuseCard['phone'] ?? null,
        ];
    }

    /**
     * Entities with a role, searched recursively (abuse contacts are often
     * nested inside the organization entity).
     *
     * @param list<array<string,mixed>> $entities
     * @return list<array<string,mixed>>
     */
    public static function entitiesWithRole(array $entities, string $role): array
    {
        $found = [];
        foreach ($entities as $entity) {
            if (in_array($role, $entity['roles'] ?? [], true)) {
                $found[] = $entity;
            }
            foreach (self::entitiesWithRole($entity['entities'] ?? [], $role) as $nested) {
                $found[] = $nested;
            }
        }
        return $found;
    }

    /**
     * jCard (RFC 7095) => flat contact fields.
     *
     * @param array<string,mixed> $entity
     * @return array{name?:string,org?:string,email?:string,phone?:string,country?:string}
     */
    public static function vcard(array $entity): array
    {
        $out = [];
        foreach ($entity['vcardArray'][1] ?? [] as $property) {
            [$name, $params, , $value] = array_pad((array) $property, 4, null);
            switch (strtolower((string) $name)) {
                case 'fn':
                    $out['name'] = trim((string) $value);
                    break;
                case 'org':
                    $out['org'] = trim(is_array($value) ? implode(' ', $value) : (string) $value);
                    break;
                case 'email':
                    $out['email'] ??= trim((string) $value);
                    break;
                case 'tel':
                    $out['phone'] ??= (string) preg_replace('/^tel:/', '', trim((string) $value));
                    break;
                case 'adr':
                    if (isset($params['cc'])) {
                        $out['country'] = (string) $params['cc'];
                    }
                    break;
            }
        }
        return array_filter($out, fn ($v) => $v !== '');
    }

    private static function registryName(?string $url): ?string
    {
        $host = (string) parse_url((string) $url, PHP_URL_HOST);
        foreach (['arin' => 'ARIN', 'ripe' => 'RIPE NCC', 'apnic' => 'APNIC', 'lacnic' => 'LACNIC', 'afrinic' => 'AFRINIC'] as $needle => $name) {
            if (str_contains($host, $needle)) {
                return $name;
            }
        }
        return $host ?: null;
    }
}
