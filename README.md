# Eurodata Keycloak Configuration

In nahezu allen eurodata Anwendungen findet sich in etwa die gleiche Keycloak Security Configuration.
Diese ist je nach Situation mit unterschiedlichen Tricks versehen, damit sie reibungsfrei funktioniert.
Dieses Projekt hilft neuen - vor allem kleinen - Anwendungen Keycloak schnell und korrekt einzusetzen.

Eurodata Clients (Server-Server und Client-Server) müssen sich regelmäßig neue JWTs holen. 
Da der Refreshvorgang kompliziert ist, wird oft für jedes Request ein neues Token von Keycloak angefragt.
Das belastet den Keycloak unnötig. 
Die `ed-keycloak-util` Bibliothek vereinfacht diesen Prozess.
Sie ermöglicht den Einsatz von `KeycloakHeader`.

In Integration Tests muss Keycloak ebenfalls eingebaut werden. 
Vor allem wenn man verschiedene Sicherheitseinstellungen testen möchte, kann dies sehr aufwendig werden. 
Mit dem durch `ed-keycloak-boot-starter` bereitgestellten `SecretTokenService` kann man pro Unit-Test ein neues Token generieren und mit neuen Berechtigungen versehen.
Dadurch lassen sich verschiedene Szenarien schnell und einfach testen.

Aktuell wird Keycloak 6.0.1 verwendet. 
Ein weiterer Vorteil ist, das alle Anwendungen gleichzeitig auf eine neue Version aktualisiert werden können.

## Maven Dependencies

Spring Boot Anwendungen können mit der folgenden Dependency alle benötigten Bibliotheken einbinden und auf eine vorbereitete `SecurityConfig` zurückgreifen.
Dies eignet sich vor allem für MicroServices mit Rest-Architektur.

```xml
        <dependency>
            <groupId>de.eurodata.keycloak</groupId>
            <artifactId>ed-keycloak-boot-starter</artifactId>
        </dependency>
```

Clients dieser Rest-APIs können mit der folgenden Dependency alle notwendigen Keycloak-Abhängigkeiten einbinden.
Hier werden zusätzlich die `SecretTokenHeader` und `KeycloakHeader` bereitgestellt, 
mit denen RestTemplates und HttpClients sichere Requests durchführen können.

```xml
        <dependency>
            <groupId>de.eurodata.keycloak</groupId>
            <artifactId>ed-keycloak-util</artifactId>
        </dependency>
```
## Eurodata-Keycloak in SpringBoot Anwendungen einbinden

Mit `ed-keycloak-boot-starter` können SpringBoot Server APIs einfacher konfiguriert werden.
Dazu müssen die Keycloak Einstellungen in der application.yml hinterlegt werden.
In Java müssen dann die entsprechenden Pfade mit Rollen geschützt werden.

### Benötigte application.yml Parameter

Die folgende Yaml Configuration sollte in eure application.yaml übernommen werden.
Dabei bedeutet `keycloak.enabled:false` nicht, dass Keycloak deaktiviert ist, sondern das SpringBoot diesen nicht autokonfiguriert.
Dies übernimmt die bereitgestellte Konfiguration.

```yml
keycloak:
    enabled: false #Autoconfig disabled - not keycloak disabled
    realm: eurodata
    auth-server-url: https://sso.eurodata.de/u/auth
    resource: <hier eurer client>
    credentials:
        secret: SECRET
    ssl-required: external
    principal-attribute: preferred_username
    use-resource-role-mappings: true
    autodetect-bearer-only: true
    token-minimum-time-to-live: 30
    cors: true
```

SECRET wird dann im Anwendungsstartup mit `keycloak.credentials.secret=...` überschrieben.
Dadurch befinden sich im Quellcode und im Repository keine Secrets.


### Authorisierung in Java einstellen

In der SecurityConfig müssen nur noch die verschiedenen Targets gesichert werden.
Bei den `antMatchers` sollte immer mit Whitelisting gearbeitet werden. 
Das bedeutet ein Zugriff der nicht explit freigegeben wurde sollte gesperrt sein.
Dies könnte z.B. mit einem  `anyRequest().hasAnyRole("ACCESS")` umgesetzt werden.
Dadurch wird ein Target, wenn es vergessen wird einzutragen, mindestens mit der Rolle `ACCESS` geschützt.
Der Aufruf von `super.configure(http);` am Anfang ist essentiell und darf nicht vergessen werden.

Rest APIs haben normalerweise per Design keine Session. 
Daher kann `csrf()` deaktiviert werden.
Die Verwendung von `cors()` kann sinnvoll sein und hängt vom Einzelfall ab.

```java
@Slf4j
@EurodataKeycloakConfiguration
public class SecurityConfig extends EurodataKeycloakSecurityConfig {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);

        http.authorizeRequests() //
                .antMatchers("/api/**").hasAnyRole("ADMIN", "USER") //
                .antMatchers("/thrift/**").hasAnyRole("ADMIN", "USER") //
                .antMatchers("/actuator/health").permitAll()     
                .antMatchers("/").permitAll()
                .anyRequest().hasAnyRole("ACCESS")
                .and()
                .csrf().disable()
                .cors().disable();

    }
}
```

### Account-Service aktivieren

Schritt 1: EurodataAccountService wie gewünscht implementieren und erweitern
```java
@Service
@Transactional
public class AccountServiceImpl implements EurodataAccountService {
    
    //Define DataKey for each custom attribute - preferable not in this class ;)
    public static final EurodataAccount.DataKey<String> FULLNAME = new EurodataAccount.DataKey<>("FULLNAME", String.class);

    @Transactional
    @Override
    public void onLogin(EurodataAccount account) {
        //onLogin you can update your database and attach further Information to the EurodataAccount
        //use DataKey pattern for type support at compile time.
        account.set(FULLNAME, "Max Mustermann");
    }
    @Override
    public Set<EurodataAuthority> loadAccountAuthorities(String accountId, Set<String> givenAuthorities) {
        //here we could access the DB to receive more authorities
        //for simplicity we just return the given authorities
        //you may use your own extension of EurodataAuthority.
        return set.stream().map(EurodataAuthority::new).collect(Collectors.toSet());
    }
```
Hinweis: Es ist zu empfehlen erst das Interface zu erweitern und dann zu implementieren. 

Schritt 2: SecurityConfig die Methode getAccountService überschreiben und dort den erzeugten AccountService zurückgeben.
```java
@Slf4j
@EurodataKeycloakConfiguration
public class SecurityConfig extends EurodataKeycloakSecurityConfig {

    
    @Autowired
    private EurodataAccountService accountService; //will be wired to your implementation :)

    @Override
    protected EurodataAccountService getAccountService() {
        return accountService;
    }
}
```


Optionaler Schritt 3: Eigene Authority Implementierung:

```java
public class ProjectXAuthority extends EurodataAuthority {

    public ProjectXAuthority(String authority) {
        super(authority);
        Nice.require(ProjectXAuthorities.exists(authority), "Authority " + authority + " not specified in cdc.");
    }

    @Override
    public String toString() {
        return "cdc(" + getAuthority() + ")";
    }
}

public class ProjectXAuthorities {
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ACCESS = "ROLE_ACCESS";
    public static final String READ_DOCUMENTATION = "READ_DOCUMENTATION";
    public static final String ADAB_TRIGGER_SEARCH = "ADAB_USE_SEARCH";
    //... weitere Authorities definieren
    

    public static final ImmutableSet<String> ALL = loadAll();

    private CdcAuthorities() {
        //NOOP
    }

    @SneakyThrows
    private static final ImmutableSet<String> loadAll() {
        HashSet<String> result = new HashSet<>();
        for (Field field : CdcAuthorities.class.getDeclaredFields()) {
            if (field.getType().equals(String.class)) {
                result.add((String) field.get(null));
            }
        }
        return ImmutableSet.copyOf(result);
    }

    public static final boolean exists(String authority) {
        return ALL.contains(authority);
    }

    public static final boolean isRole(String authoritiy) {
        return authoritiy.startsWith("ROLE_") && exists(authoritiy);
    }
}
```


### Method Security aktivieren

```java
@Import({EurodataMethodSecurityConfig.class}) //<--- lädt die Default Einstellungen
@EurodataKeycloakConfiguration
public class SecurityConfig extends EurodataKeycloakSecurityConfig {
    //...
}
```

Method-Security sollte nur in Controllern - nicht in Services eingesetzt werden. Weitere Informationen über die
Verwendung auf https://www.baeldung.com/spring-security-method-security

Grundsätzlich können die Authorities via String abgeprüft werden:

```java
class ExampleController {
    
    @Secured("ROLE_ADMIN")
    @GetMapping("/{id}")
    public HttpEntity<RAccount> getById(@PathVariable("id") String id) {
      //...
        return null;
    }
}
```

### React-Helper aktivieren

Zuerst den RestController aktivieren und die benötigten Endpoints freigeben.
```java
@Slf4j
@Import({EurodataKeycloakRestController.class}) //<--- IMPORT aktiviert Endpoint
@EurodataKeycloakConfiguration
public class SecurityConfig extends EurodataKeycloakSecurityConfig {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
            http
                //endpoint freigeben
                .antMatchers("/keycloak.js").permitAll()
                .antMatchers("/keycloak-client-config").permitAll()
                //blacklist all which are not whitelisted:
                .anyRequest().hasAnyAuthority("ROLE_ACCESS")
                .and()
                .csrf().disable()
                .cors().disable();
    }
                    
    
    
}
```
`/keycloak.js` erzeugt eine 302 Weiterleitung auf den Keycloak-Server
`/keycloak-client-config` liefert die in der yml spezifizierten Werte für einen Keycloak Client als JSON.

In der Yaml noch die Werte für den Client eintragen:
```yaml
keycloak-client:
  url: https://sso.eurodata.de/u/auth
  clientId: <your client>
  realm: eurodata
```


## JUnit Tests mit Berechtigung ohne Keycloak

Der `SecretTokenService` kann einfach in Unit-Tests via `@Autowire` eingebunden werden.
Darüber lassen sich neue Tokens zur Laufzeit erstellen, die verschiedene Berechtigungen haben.
Diese Umgehen Keycloak und können so auch offline ohne funktionierende Keycloak Umgebung eingesetzt werden.

`SecretTokens` sollten nicht permanent erzeugt werden um ein Backdoor zu schaffen. 
Sie sollten am besten nur in UnitTests verwendet werden.
Ein SecretToken ist üblicherweise eine 128 Bit mit SecureRandom gezogene UUID.
Korrekt eingesetzt gilt dieses Vorgehen als sicher.
Ein verlorenes `SecretToken` muss direkt invalidiert werden.
Wird ein SecretToken über HTTP (nicht über HTTPS) übermittelt sollte es als kompromitiert angesehen werden.

Im folgenden Beispiel wird ein RestTemplate erzeugt, welches Aufrufe mit der Berechtigung `ROLE_ADMIN`, `ROLE_ACCESS` und `ROLE_USER` ausführt.

```java
class Test {
    
    @Autowired
    SecretTokenService sts;


    @Test
    public void test(){
        String secret = UUID.randomUUID().toString();
        SecretToken token = sts.registerSecretToken(secret, "ROLE_ADMIN");
        token.getAccountInfo().setEmail("test@test.de");
        token.getAccountInfo().setFirstName("Max");
        token.getAccountInfo().setLastName("Mustermann");
        
        SecretTokenAuthenticator authenticator = sts.createAuthenticator(secret);


        
        
        RestTemplate template = new RestTemplate();
        template.setInterceptors(Arrays.asList((ClientHttpRequestInterceptor) (HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
            EdAuthHeader authHeader = authenticator.getHeader();
            request.getHeaders().set(authHeader.getKey(), authHeader.getValue());
            return execution.execute(request, body);
        }));
        
        //do unit tests with template :)
    }
}
```


## Client-Server KeycloakHeader

Client Anwendungen welche eine API auf einem Server aufrufen können den `KeycloakHeader` verwenden.
Dieser Header ermittelt automatisch ein JWT über keycloak und verwendet diesen.
Jedesmal wenn der Header eingsetzt wird, wird das Token lokal überprüft und ggf. aktualisiert.
Die Aktualisierung findet statt, wenn das Token in der nächsten Sekunde abläuft.
Mit `setRefreshBefore` kann diese Zeit modifiziert werden.
Dies ist erforderlich, wenn mit hohen Latenzen zu rechnen ist.

Keycloak-Token sind üblicherweise 5 Minuten gültig. 
Die mehrfache Verwendung des selben Token ist wünschenswert um den Keycloak-Server zu entlasten.
Die Validierung des Token wird so auf den Client verschoben.

```java
class Example {
    
    public static void main(){
      //config url can also be passed to the AuthenticatorFactory directly 
      KeycloakClientConfig config = KeycloakClientConfig.createResolver("https://apps.eurodata.de/a/xyz/keycloak-client-config").get();
      
      Authenticator authenticator = AuthenticatorFactory.getDefault().createUserPassword(
                    config.getUrl(), //auth
                    config.getRealm(), //realm
                    config.getClientId(), //resource
                    "test@test.de", //user
                    "****"); //passwort
       
      RestTemplate template = new RestTemplate();
        template.setInterceptors(Arrays.asList((ClientHttpRequestInterceptor) (HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
            EdAuthHeader authHeader = authenticator.getHeader();
            request.getHeaders().set(authHeader.getKey(), authHeader.getValue());
            return execution.execute(request, body);
      }));
    }
}
```

## Server-Server KeycloakHeader

Die selbe Technik kann auch für Server-Server-Requests eingesetzt werden.
Dazu wird dann ein Client-Secret anstatt User und Passwort benötigt.


```java
class Example {
    
    public static void main(){
      Authenticator authenticator = AuthenticatorFactory.getDefault().createClientSecret(
                "<auth url>", //auth
                "<realm>", //realm
                "<client-id>", //resource
                "<client secret>"); //client-secret
    }
}
```

 
