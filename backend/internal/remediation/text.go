package remediation

import (
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

// texts are the words of one notice language: the issue titles, evidence and advice that
// appear in a notice, the notice itself and the chat card facts. Technical identifiers
// (product names, versions, CVE ids, addresses, ISO dates) are passed in unchanged.
// English is also the language of the analyst UI (ticket titles, history, digest).
type texts struct {
	lang string

	vulnTitle, vulnEvidence, vulnDistro, vulnAdvice   string
	eolTitle, eolEvidence, eolDistro, source          string
	eolAdviceTo, eolAdvice                            string
	clearTitle, clearEvidence, clearAdvice            string
	expTitle, expEvidence, expAdvice                  string
	adminTitle, adminTitleNamed, adminEvidence        string
	adminAt, adminPageTitle, adminAdvice              string
	stagingTitle, stagingEvidence, stagingAdvice      string
	hostTitle, hostEvidence, hostAdvice               string
	svcTitle, svcEvidence, svcAdvice                  string
	unknownService, unidentifiedService               string
	via                                               map[string]string
	vulnNames                                         map[string]string
	subject, greeting, greetingNamed, intro, introFor string
	fWhat, fWhere, fService, fEvidence, fFirstSeen    string
	fTodo                                             string
	askBy, ask                                        map[string]string
	recheck, notYours, signoff                        string
	factWhere, factOwner, factDue                     string
	ownerUnknown, dueNotSet                           string
	testSubject, testBody                             string
}

var textEN = &texts{
	lang: locale.EN,

	vulnTitle:    "%[1]s %[2]s may be affected by %[3]s (%[4]s)",
	vulnEvidence: "Version-only hint: %[1]s %[2]s is in the range affected by %[3]s (%[4]s). Nothing was sent to the service to confirm it.",
	vulnDistro:   " Distribution build: the fix may be backported, check the package version.",
	vulnAdvice:   "Install the vendor fix (or the distribution update that carries it), or take the service off the network.",

	eolTitle:    "%[1]s %[2]s is end of life since %[3]s",
	eolEvidence: "%[1]s %[2]s seen via %[3]s. Branch %[4]s stopped getting security fixes on %[5]s.",
	eolDistro:   " Distribution build: fixes may be backported, but the upstream branch is unsupported.",
	source:      " Source: ",
	eolAdviceTo: "Upgrade to %[1]s %[2]s or newer, or remove the service if nobody needs it.",
	eolAdvice:   "Upgrade to a supported release, or remove the service if nobody needs it.",

	clearTitle:    "%[1]s (cleartext login) open on %[2]s",
	clearEvidence: "Port %[1]d answers as %[2]s. Passwords sent over it can be read by anyone on the path.",
	clearAdvice:   "Turn off %[1]s and use an encrypted alternative (SSH, SFTP).",

	expTitle:    "%[1]s reachable on %[2]s",
	expEvidence: "Port %[1]d/%[2]s (%[3]s) answers from the scanning network.",
	expAdvice:   "Close the port, or allow it only from the networks that need it (firewall, VPN).",

	adminTitle:      "Admin panel exposed on %[1]s",
	adminTitleNamed: "%[1]s exposed on %[2]s",
	adminEvidence:   "Admin login or management console detected",
	adminAt:         " at %s",
	adminPageTitle:  " (page title %q)",
	adminAdvice:     "Allow the admin panel only from VPN or an allowlist, or remove it from this network.",

	stagingTitle:    "Test or staging instance exposed on %s",
	stagingEvidence: "The service looks like a development or staging instance (name, title or headers).",
	stagingAdvice:   "Remove the instance if it is not needed, or put it behind VPN.",

	hostTitle:           "Host %s needs review",
	hostEvidence:        "Seen on the network by CBI AGH monitoring.",
	hostAdvice:          "Confirm the host is needed and patched, or remove it.",
	svcTitle:            "Service %[1]s on %[2]s:%[3]d needs review",
	svcEvidence:         "Port %[1]d/%[2]s is open (%[3]s).",
	svcAdvice:           "Confirm the service is needed and patched; otherwise close the port.",
	unknownService:      "unknown",
	unidentifiedService: "unidentified service",

	subject:       "[CBI AGH] Action needed: %s",
	greeting:      "Hello,",
	greetingNamed: "Hello %s,",
	intro:         "Our network monitoring found an issue on a host you manage.",
	introFor:      "Our network monitoring found an issue on a host you manage.",
	fWhat:         "What",
	fWhere:        "Where",
	fService:      "Service",
	fEvidence:     "Evidence",
	fFirstSeen:    "First seen",
	fTodo:         "What to do",
	askBy: map[string]string{
		ActionPatch:    "Please patch it by %s and reply when done.",
		ActionRemove:   "Please remove it by %s and reply when done.",
		ActionRestrict: "Please restrict access to it by %s and reply when done.",
		"":             "Please fix it by %s and reply when done.",
	},
	ask: map[string]string{
		ActionPatch:    "Please patch it and reply when done.",
		ActionRemove:   "Please remove it and reply when done.",
		ActionRestrict: "Please restrict access to it and reply when done.",
		"":             "Please fix it and reply when done.",
	},
	recheck:  "We check again after every scan and close this request once the issue is gone.",
	notYours: "If this host is not yours, please tell us who manages it.",
	signoff:  "CBI AGH security team",

	factWhere:    "Where",
	factOwner:    "Owner",
	factDue:      "Due",
	ownerUnknown: "unknown",
	dueNotSet:    "not set",

	testSubject: "Dzięcioł test message",
	testBody:    "This is a test from Dzięcioł. If you can read it, owner notifications and the digest will reach you here.",
}

// textPL is plain, formal Polish ("Państwo" register) for faculty administrators.
var textPL = &texts{
	lang: locale.PL,

	vulnTitle:    "Możliwa podatność %[3]s (%[4]s) w %[1]s %[2]s",
	vulnEvidence: "Ocena wyłącznie na podstawie numeru wersji: %[1]s %[2]s mieści się w zakresie wersji podatnych na %[3]s (%[4]s). Usługi nie testowano, aby to potwierdzić.",
	vulnDistro:   " To wersja z dystrybucji systemu: poprawka mogła zostać przeniesiona (backport), prosimy sprawdzić wersję pakietu.",
	vulnAdvice:   "Zainstalować poprawkę producenta (albo aktualizację z dystrybucji, która ją zawiera) lub odłączyć usługę od sieci.",

	eolTitle:    "%[1]s %[2]s bez wsparcia (EOL) od %[3]s",
	eolEvidence: "Wersję %[1]s %[2]s rozpoznano na podstawie %[3]s. Gałąź %[4]s nie otrzymuje poprawek bezpieczeństwa od %[5]s.",
	eolDistro:   " To wersja z dystrybucji systemu: poprawki mogą być przenoszone (backport), ale sama gałąź nie jest już wspierana przez autorów.",
	source:      " Źródło: ",
	eolAdviceTo: "Zaktualizować %[1]s do wersji %[2]s lub nowszej albo wyłączyć usługę, jeśli nie jest potrzebna.",
	eolAdvice:   "Zaktualizować do wspieranej wersji albo wyłączyć usługę, jeśli nie jest potrzebna.",

	clearTitle:    "Logowanie bez szyfrowania (%[1]s) na %[2]s",
	clearEvidence: "Port %[1]d odpowiada jako %[2]s. Hasła przesyłane tym protokołem może odczytać każdy, kto ma dostęp do ruchu po drodze.",
	clearAdvice:   "Wyłączyć %[1]s i korzystać z szyfrowanej alternatywy (SSH, SFTP).",

	expTitle:    "Usługa %[1]s dostępna z sieci na %[2]s",
	expEvidence: "Port %[1]d/%[2]s (%[3]s) odpowiada z sieci, z której prowadzimy skanowanie.",
	expAdvice:   "Zamknąć port albo dopuścić ruch tylko z sieci, które go potrzebują (firewall, VPN).",

	adminTitle:      "Panel administracyjny dostępny na %[1]s",
	adminTitleNamed: "Panel administracyjny %[1]s dostępny na %[2]s",
	adminEvidence:   "Wykryto stronę logowania administratora lub konsolę zarządzania",
	adminAt:         " pod adresem %s",
	adminPageTitle:  " (tytuł strony: „%s”)",
	adminAdvice:     "Udostępnić panel administracyjny tylko przez VPN lub z listy dozwolonych adresów albo usunąć go z tej sieci.",

	stagingTitle:    "Środowisko testowe dostępne na %s",
	stagingEvidence: "Usługa wygląda na instancję deweloperską lub testową (nazwa, tytuł strony albo nagłówki).",
	stagingAdvice:   "Usunąć instancję, jeśli nie jest potrzebna, albo udostępnić ją tylko przez VPN.",

	hostTitle:           "Host %s wymaga weryfikacji",
	hostEvidence:        "Host został wykryty w sieci przez monitoring CBI AGH.",
	hostAdvice:          "Potwierdzić, że host jest potrzebny i ma aktualne oprogramowanie, albo go wyłączyć.",
	svcTitle:            "Usługa %[1]s na %[2]s:%[3]d wymaga weryfikacji",
	svcEvidence:         "Port %[1]d/%[2]s jest otwarty (%[3]s).",
	svcAdvice:           "Potwierdzić, że usługa jest potrzebna i aktualna, a w przeciwnym razie zamknąć port.",
	unknownService:      "nieznana",
	unidentifiedService: "nierozpoznana usługa",

	// "na podstawie ..." takes the genitive.
	via: map[string]string{
		"nmap":               "wyniku nmap -sV",
		"cpe":                "identyfikatora CPE z nmap",
		"banner":             "baneru usługi",
		"http-server-header": "nagłówka Server",
		"http-page":          "treści strony HTTP",
		"x-powered-by":       "nagłówka X-Powered-By",
		"technology":         "rozpoznanej technologii",
	},
	vulnNames: map[string]string{
		"CVE-2024-6387":    "regreSSHion, zdalne wykonanie kodu bez uwierzytelnienia w obsłudze sygnału SIGALRM w sshd",
		"CVE-2021-41773":   "path traversal i zdalne wykonanie kodu w Apache httpd 2.4.49",
		"CVE-2021-42013":   "path traversal i zdalne wykonanie kodu w Apache httpd 2.4.49 i 2.4.50, niepełna poprawka CVE-2021-41773",
		"CVE-2019-10149":   "Exim „Return of the WIZard”, zdalne wykonanie poleceń",
		"CVE-2017-1001000": "wstrzyknięcie treści przez REST API WordPressa, zmiana wpisów bez uwierzytelnienia",
		"CVE-2017-16510":   "SQL injection w $wpdb->prepare() w WordPressie",
		"CVE-2015-1419":    "obejście ograniczenia dostępu deny_file w vsftpd",
	},

	subject:       "[CBI AGH] Wymagane działanie: %s",
	greeting:      "Szanowni Państwo,",
	greetingNamed: "Szanowni Państwo,",
	intro:         "Nasz system monitorowania sieci wykrył problem na hoście, którym Państwo administrują.",
	introFor:      "Nasz system monitorowania sieci wykrył problem na hoście, którym Państwo administrują (w naszej ewidencji: %s).",
	fWhat:         "Problem",
	fWhere:        "Adres",
	fService:      "Usługa",
	fEvidence:     "Szczegóły",
	fFirstSeen:    "Pierwsze wykrycie",
	fTodo:         "Zalecenie",
	askBy: map[string]string{
		ActionPatch:    "Prosimy o aktualizację w terminie do %s i o odpowiedź na tę wiadomość po zakończeniu prac.",
		ActionRemove:   "Prosimy o wyłączenie usługi w terminie do %s i o odpowiedź na tę wiadomość po zakończeniu prac.",
		ActionRestrict: "Prosimy o ograniczenie dostępu w terminie do %s i o odpowiedź na tę wiadomość po zakończeniu prac.",
		"":             "Prosimy o usunięcie problemu w terminie do %s i o odpowiedź na tę wiadomość po zakończeniu prac.",
	},
	ask: map[string]string{
		ActionPatch:    "Prosimy o aktualizację i o odpowiedź na tę wiadomość po zakończeniu prac.",
		ActionRemove:   "Prosimy o wyłączenie usługi i o odpowiedź na tę wiadomość po zakończeniu prac.",
		ActionRestrict: "Prosimy o ograniczenie dostępu i o odpowiedź na tę wiadomość po zakończeniu prac.",
		"":             "Prosimy o usunięcie problemu i o odpowiedź na tę wiadomość po zakończeniu prac.",
	},
	recheck:  "Sprawdzamy ten adres po każdym skanowaniu i zamkniemy zgłoszenie, gdy problem przestanie występować.",
	notYours: "Jeśli ten host nie należy do Państwa, prosimy o informację, kto nim administruje.",
	signoff:  "Z poważaniem\nZespół bezpieczeństwa CBI AGH",

	factWhere:    "Adres",
	factOwner:    "Właściciel",
	factDue:      "Termin",
	ownerUnknown: "nieznany",
	dueNotSet:    "nie ustalono",

	testSubject: "Dzięcioł: wiadomość testowa",
	testBody:    "To jest wiadomość testowa z systemu Dzięcioł. Jeśli ją Państwo widzą, powiadomienia dla właścicieli i poranny raport dotrą w to miejsce.",
}

// textFor returns the texts of a notice language (English for unknown codes).
func textFor(lang string) *texts {
	if locale.Lang(lang) == locale.PL {
		return textPL
	}
	return textEN
}

// TestMessage is the subject and body of the "Send test" message in lang.
func TestMessage(lang string) (string, string) {
	t := textFor(lang)
	return t.testSubject, t.testBody
}

func (t *texts) viaLabel(via string) string {
	if l := t.via[via]; l != "" {
		return l
	}
	return via
}

func (t *texts) vulnName(id, name string) string {
	if n := t.vulnNames[id]; n != "" {
		return n
	}
	return name
}
