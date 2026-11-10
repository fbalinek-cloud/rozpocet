# Rozpočet Balínkovi

Společný rodinný rozpočet pro dva telefony. Běží jako webová appka na GitHub Pages, data se synchronizují přes Supabase.

## Zabezpečení

- Všechna data se šifrují přímo v telefonu (AES-256-GCM) klíčem odvozeným z **hesla domácnosti** (PBKDF2, 310 000 iterací).
- Do Supabase odchází jen nečitelné bloky. Heslo ani klíč server nikdy nevidí.
- Telefon se přihlašuje anonymně, k datům domácnosti ho pustí až správný kód a heslo (ověřuje se otisk odvozeného tokenu).
- Přístup k řádkům hlídají pravidla Row Level Security.
- Když heslo zapomenete a odhlásíte oba telefony, data nejde obnovit.

## Nastavení Supabase (jednou)

1. Nový projekt, region Frankfurt (eu-central-1).
2. Authentication → Sign In / Providers → zapnout **Allow anonymous sign-ins**.
3. SQL Editor → vložit obsah `supabase/schema.sql` → Run.
4. Project Settings → API: zkopírovat **Project URL** a **anon / publishable key** do `config.js`.

## Použití

1. Otevřít adresu appky v Safari → Sdílet → **Přidat na plochu**.
2. První telefon: **Založit domácnost**, nechat vygenerovat heslo a uložit ho do Klíčenky.
3. Druhý telefon: **Připojit se**, zadat kód a heslo.
4. Ve Více → Nastavení → Nahrát zálohu lze načíst data z předchozí verze.

## Soubory

- `index.html` – celá appka
- `config.js` – adresa a veřejný klíč Supabase
- `supabase/schema.sql` – tabulky, pravidla přístupu a funkce
- `sw.js`, `manifest.webmanifest`, `icons/` – instalace na plochu a offline režim
- `vendor/supabase.js` – knihovna supabase-js 2.45.4
