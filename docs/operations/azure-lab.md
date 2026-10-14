# Azure lab: AD DC + AD connector (cloud replica)

Replica in cloud, isolata, dell'esperimento locale: un Domain Controller in una
VNet dedicata e il connettore AD come Web App Linux container. Serve a validare
in cloud lo stesso flusso `Update_User_Profile` provato in locale, senza toccare
il tenant Entra esistente e senza esporre AD su internet.

## Architettura

```
Azure  rg-aiw-agents-neu-001  (North Europe)
├── adlab-vnet  10.20.0.0/16
│   ├── snet-dc      10.20.1.0/24   -> vm-dc01 (Windows Server, AD DS, LDAPS 636, solo IP privato)
│   └── snet-webapp  10.20.4.0/26   -> VNet integration della Web App (delega Microsoft.Web)
├── nsg-adlab (su snet-dc)
├── stmadlabneu001 + share Azure Files "mwa-state"  (state SQLite del connettore)
└── app-mwa-adconn-neu-001  (Linux container) sul piano esistente asp-helpdesk-prd-neu
```

- Dominio lab: `corp.test.local`, DC `vm-dc01.corp.test.local` (10.20.1.4).
- Il connettore usa LDAPS (636) verso il DC **dentro la VNet**; nessuna porta
  pubblica, nessun Bastion. L'accesso alle VM avviene solo via control plane
  Azure (`az vm run-command`).
- Pull immagine ACR via **system-assigned managed identity + AcrPull**
  (nessuna password registry negli app settings).

## Prerequisiti (da fornire una tantum)

**GitHub → Environment `lab`** sul repo `DarioTortorici/activeconnector`:

| Tipo | Nome | Note |
|---|---|---|
| secret | `AZURE_CLIENT_ID` | App registration OIDC |
| secret | `AZURE_TENANT_ID` | tenant dell'App (non quello delle risorse, se diverso) |
| secret | `AZURE_SUBSCRIPTION_ID` | subscription con `rg-aiw-agents-neu-001` |
| secret | `LABADMIN_PASSWORD` | admin locale VM (12-123, 3 su 4 classi) |
| secret | `DSRM_PASSWORD` | Directory Services Restore Mode |
| secret | `SVC_MWA_PASSWORD` | password AD di `svc-mwa` **e** bind del connettore |
| secret | `TESTUSER_PASSWORD` | password iniziale di `tuser1` |
| secret | `MWA_JWT_SECRET` | HMAC token agent↔connettore (32+ byte) |
| secret | `MWA_PAGE_TOKEN_SECRET` | HMAC cursori di paginazione |

**Permessi dell'App OIDC** (nel tenant delle risorse): `Contributor` su
`rg-aiw-agents-neu-001`, `AcrPush` e `User Access Administrator` su
`crhelpdeskprd`. `AcrPush` serve per pubblicare l'immagine; `User Access
Administrator` e' **obbligatorio** perche' il deploy concede `AcrPull`
all'identita' della web app (senza, il container non scarica l'immagine:
`ACRTokenRetrievalFailure`). Nessun secret ACR (pull via managed identity).

## Deploy

`Actions → deploy-lab → Run workflow` (`main`). Job in ordine:
`infra` → `dc` → `image` → `webapp` → `verify`. Durata ~45-60 min (dominio +
reboot). Idempotente: si puo' rilanciare; le risorse esistenti vengono saltate.

Esito atteso nel job `verify`: `health: HEALTHY`, `LDAPS…True`,
`resolve object_guid: …`, `dry-run: AUTHORIZED`.

### Test end-to-end (senza redeploy)

`Actions → lab-test → Run workflow`: esegue `health → resolve → update` su
`tuser1` contro il lab gia' deployato, **senza modificare l'infrastruttura**.
Con `apply=true` (default) fa la scrittura reale → atteso `state=AD_VERIFIED`;
con `apply=false` solo dry-run. Da usare dopo `lab-start` o per le demo.

## Stop / Start (risparmio costi)

- **`lab-stop`** (Actions → lab-stop → Run): `az vm deallocate` della VM DC →
  costo compute azzerato. Restano solo dischi/storage (pochi centesimi/giorno).
- **`lab-start`** (Actions → lab-start → Run): riaccende la VM e attende LDAPS
  636. L'IP privato 10.20.1.4 e' invariato, il connettore la ritrova subito.

Il NAT di bootstrap e il suo public IP sono gia' **rimossi a fine `deploy-lab`**,
quindi il lab fermo non paga risorse di rete sempre-accese.

## Teardown

Rimuovere le sole risorse del lab (NON cancellare il resource group condiviso):

```bash
az vm delete -g rg-aiw-agents-neu-001 -n vm-dc01 --yes
az webapp delete -g rg-aiw-agents-neu-001 -n app-mwa-adconn-neu-001
az storage account delete -g rg-aiw-agents-neu-001 -n stmadlabneu001 --yes
az network vnet delete -g rg-aiw-agents-neu-001 -n adlab-vnet
az network nsg delete -g rg-aiw-agents-neu-001 -n nsg-adlab
```

> Mai `az group delete -n rg-aiw-agents-neu-001`: contiene risorse condivise
> (Cosmos, OpenAI, ACR, le app helpdesk). La pipeline non contiene alcun comando
> distruttivo.

## Diagnosis rapida

```bash
# stato VM + estensione
az vm get-instance-view -g rg-aiw-agents-neu-001 -n vm-dc01 \
  --query "instanceView.statuses[].displayStatus" -o tsv
# health connettore (pubblico)
curl https://app-mwa-adconn-neu-001.azurewebsites.net/api/v1/health
# log connettore
az webapp log tail -g rg-aiw-agents-neu-001 -n app-mwa-adconn-neu-001
```

## Note e insidie del lab (imparate sul campo)

1. **Bootstrap DNS**: all'inizio la VNet NON deve avere DNS custom. La VM del DC
   usa il DNS di Azure per scaricare gli script dell'estensione; se la VNet punta
   a 10.20.1.4 prima della promozione, la risoluzione fallisce e l'estensione
   resta in "Downloading files from storage". Il `deploy-lab` punta il DNS al DC
   **solo alla fine** del job `dc`.
2. **Egress di bootstrap**: le VM create senza public IP e senza
   `defaultOutboundAccess` non hanno uscita internet. Il `deploy-lab` crea un
   **NAT Gateway** per la durata del bootstrap e lo elimina a fine job.
3. **FQDN del DC**: la VM si chiama `vm-dc01`, quindi il suo FQDN e' sempre
   `vm-dc01.corp.test.local` (non `DC01...`). Certificato LDAPS e `MWA_AD_DC_HOST`
   devono coincidere col FQDN reale, altrimenti la validazione TLS fallisce.
4. **Read-after-write**: la projection di lettura del connettore deve includere
   gli attributi scrivibili (givenName, sn, ...), altrimenti un commit riuscito
   viene riportato come `FAILED_VERIFICATION` (502).
5. **Delega ACL**: `svc-mwa` va delegato (Read/Write sugli attributi allowlisted)
   su **ogni** OU gestita, non solo su `OU=Managed`. Senza delega: `403
   LDAP_INSUFFICIENT_ACCESS` (AD result 50).
6. **`X-Ticket-ID`**: il connettore lo pretende su ogni mutazione; l'agent deve
   inviarlo (i tool parity EntraMCP non hanno il concetto di ticket: viene
   sintetizzato).
7. **Pull immagine ACR**: la web app scarica l'immagine con la propria managed
   identity, quindi serve `AcrPull` su `crhelpdeskprd`; il deploy lo concede, ma
   richiede che l'App di deploy abbia `User Access Administrator` sull'ACR.
   Senza: `ACRTokenRetrievalFailure` (Unauthorized) nei log container e health
   503/timeout. Il job `webapp` ora verifica il grant e fallisce esplicitamente.

## Modifiche al codice necessarie (gia' presenti)

- `activeconnector` `infrastructure/ldap/common.py` + `reads.py`: attributi
  scrivibili nella read projection (fix 4).
- `hybrid-agent-app` `apps/identity-agent/.../tools_impl.py`: mint di
  `X-Ticket-ID` sulle mutazioni (fix 6).
- `scripts/azure/*`: Dockerfile Linux, entrypoint container, bootstrap DC
  (part1/part2), verifica DC, verifica cloud, delega OU.
