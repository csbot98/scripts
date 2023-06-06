A script két részből áll:
	-GenCSR:
Csinál egy privát kulcsot és egy hozzávaló CSR filet egy előre definiált CNF fájl alapján, amit majd egy CA szerverre kell továbbítani, hogy a kliens cert létre tudjon jönni.
--
|client.cnf| == client.key & client.csr ~> CA szerver
--
	-Import:
A GenCSR-el generált fájlok alapján létrehozott kliens cert a kiindulási alap, szükséges még egy CA cert (egy intermediateCA cert, de ez csak opcionális). 
Ezekből először lesz egy .pem fájl. 
Ebből a .pem fájból kreálunk egy -DER.key fájlt.
És végül ezek segítségével létrejön a .p12 fájl. (A script elején bekérjük a felhasználótól a jelszót a p12 fájlhoz. Majd a script végeztével, törlésre kerül. Ugyanaz lesz a jelszó minden p12 fájlhoz.)
Ezután jön a fájlok elhelyezése:
Az IBM-es all_server.sh scriptet használva kiszórjuk az EventCollectoroknak (EC) a certeket (p12). Ez úgy épül fel, hogy mindennek ugyanaz a neve: a CNF fájl neve monjduk teszt1, akkor a csr és a key fájl is ugyanazt a nevet kapja. A CA szerveren bármilyen nevet kaphat a cert, amint az "Import" megkapja a fájlt a cert nevét veszi alapul és aszerint csinálja meg a fájlokat.
Végül a cert nevét összeveti az etc/hosts fájlban található hostname-el és ha talál egyezést, akkor az all_serverrel kiszórja annak a kliensnek. [Így tanácsos mindennemű fájlt úgy elnevezni, ahogy az a hosts-ban is van.]
A qradar által előírt helyre szórja ki a fájlokat, a keystoret is legenerálja majdan pedig restartolja a megfelelő service-t. (Ez csak azért van kikommentelve jelenleg mert rendesen éles környezetben nem tudtam tesztelni csakis próbateszt során, viszont ott müködott.)
Ha ez is megvan akkor az alap fájlokat (pem, p12, key, ha van akkor csr) egy mappába rakja és tömöríti.
--
CA cert | client cert <intermediateCA> ~> client.pem
client.pem ~> client-DER.key
client.pem + client-DER.key ~> client.p12
--
