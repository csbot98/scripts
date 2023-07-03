#!/bin/bash

#Tutorial:
#-Install: az EasyRSA-t lehet ezzel feltelepíteni (CA-nak).
#-GenCNF: CNF fájl generál (elsődlegesen a DLC-nek lett szánva)
#-GenCSR: Generál egy előre megadott CNF fájl alapján egy privát kulcsot és hozzá egy CSR fájlt, amit aztán majd alá kell írni.
#-GenCert: Generál EasyRSA-val egy aláírt kliens certet.
#-Import: a már aláírt (visszakapott) cert(ek) alapján generál egy .pem, .p12, -DER.key fájlt, majd ha ugyanaz a cert base név és ami az etc/hosts-ban is megvan adva, a fájlok az "all_server.sh" scriptet használva, kiosztásra kerülnek.
#-DLCImport: A keytoolba beimportálja a root ca certeket + ha generáltunk egy CSR-t és azt aláíratjuk a CA szerverrel és azt "visszaadjuk", akkor .p12 fájlt generál.

#FONTOS: minden fájlnak ('.crt', '.key, '_CA.crt' és esetleg az intermediateCA ami szintén ".crt" csak külön mappában), ugyanaz kell legyen a nevük! ['teszt.crt', 'teszt.key, 'teszt_CA.crt']

########
#Innen olvassa fel a certeket (signed xy.crt & CA.key & intermediateCA.crt).
CA_CERT_DIR="$(pwd)/ca"
CERT_DIR="$(pwd)/cert"
INTERMEDIATE_CA_DIR="$(pwd)/intermediateCA"
ANCHORS="/etc/pki/ca-trust/source/anchors"
########

OPENSSL_CMD="/usr/bin/openssl"
CAT_CMD="/usr/bin/cat"
ALL_SERVER_CMD="/opt/qradar/support/all_servers.sh"
IP_ADDRESS=$(hostname -I | awk '{print $1}')
FQDN=$(hostname -f)

#Keytool loc.	#ha esetleg nem találná a sima "keytool" parancsot.
results=$(find / -name "jre" 2>/dev/null)
KEYTOOL_CMD=$results/bin/keytool


#EasyRSA install mappa
EASYRSA_INSTALL_DIR="$(pwd)/EasyRSA"
EASYRSA_DIR="$EASYRSA_INSTALL_DIR/EasyRSA-3.0.8"

#########
###############CNF#########
#Ha nincs CNF fájl, az alábbi adatokat megadva létre lehet hozni. 
COMMON_NAME="10.35.116.177"
ORG_NAME="T-Teszt"
ORG_UNIT="T-TesztU"
###########################
#########

#Ezt leginkább a ca jelszó tárolása miatt használom.
SOURCE_DIR="$(pwd)"

#Innen olvassa fel a .CNF fájlt a CSR Fájl generáláshoz.
CNF_DIR="$(pwd)/cnf"

#Ide kerül mentésre .csr és a private key.
CSR_DIR="$(pwd)/csr"
KEY_DIR="$(pwd)/key"

#Ide kerülnek majd az elkészült fájlok backup gyanánt. Sima mappába és tömörített verzióban is.
COMPRESSED_FINAL_DIR="$(pwd)/compressed_final"

#Végén ebbe a mappába kerül majd az újonnan generált fájlok hada (.pem, .der, .p12).
QRADAR_DIR="/opt/qradar/conf/trusted_certificates/"
#QRADAR_DIR="/tmp/teszt"

#Keytool
DEST_KEY_DIR="/opt/qradar/conf"
KEYTOOL_ALIAS="syslog-tls"

#DLC
##A fájlok neve meg kell egyezzen az adott gép FQDN-vel.
	#Keystore
KEYSTORE_ROOT_ALIAS_NAME="client_root_ca"
KEYSTORE_INT_ALIAS_NAME="client_int_ca"
KEYSTORE_NAME="clientca"	#ezt kell átírni, ha másik trust store fájl akarunk. A default trust store neve: cacerts
	#Client_CA
CLIENT_ROOT_CA="${CA_CERT_DIR}/ca.crt"
CLIENT_INT_CA="${INTERMEDIATE_CA_DIR}/$root_int_ca.crt"
	#CNF_for_DLC (mostly)
CNF_FILE="${CNF_DIR}/${FQDN}.cnf"
	#Convert
CLIENT_CERT_CRT="${CERT_DIR}/${FQDN}.crt"
CLIENT_CERT_PEM="${CERT_DIR}/${FQDN}.pem" 
INT_CA_PEM_FILE="${INTERMEDIATE_CA_DIR}/${FQDN}-int.pem"
INT_CA_CRT_FILE="${INTERMEDIATE_CA_DIR}/${FQDN}-int.crt"
	#Final file
KEY_FILE="${KEY_DIR}/${FQDN}.key"
DLC_P12_FILE="${CERT_DIR}/${FQDN}.p12"
KEY_STORES="/opt/qradar/conf/key_stores"
# KEY_STORES="$(pwd)/teszt"
##############

	if [[ $# -eq 0 ]]; then
		echo "Usage: $0 [-Install] [-GenCNF] [-GenCert] [-GenCSR] [-Import] [-DLCImport]"
		echo ""
		echo "Note: -Install: EasyRSA first install and inicialization."
		echo "Note: -GenCNF: Create CNF file (Recommended for DLC) [serverAuth,clientAuth]."
		echo "Note: -GenCSR: Create CSR and private key for client cert."
		echo "Note: -GenCert: Create (self-signed) client cert with EasyRSA."
		echo "Note: -Import: Create P12 and other files and import to QRadar."
		echo "Note: -DLCImport: Setting up certificate-based authentication on DLC."
		echo ""
	exit 1
	fi

	###################################################################################################
		#[Install] mode	|	Mode 1
	###################################################################################################

	if [[ "$1" == "-Install" ]]; then
	
		echo "####################"
		echo "EasyRSA first install mode selected"
		echo ""
		
	# Check if the directory exists
		if [ ! -d "$EASYRSA_INSTALL_DIR" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: $EASYRSA_INSTALL_DIR"
			mkdir "$EASYRSA_INSTALL_DIR"
			echo "Success!: The ${EASYRSA_INSTALL_DIR} directory has been created!"
			echo ""
		fi
		
		# Letöltjük az easyrsa-t és kicsomagoljuk a temporary mappába
		wget -O - https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz | tar xzf - -C $EASYRSA_INSTALL_DIR
		
		# Navigálunk a temporary mappába, ahol az easyrsa kicsomagolódott
		cd $EASYRSA_DIR/
		
		# Inicializáljuk a PKI-t
		./easyrsa init-pki

		# Kiadjuk a build-ca parancsot
		./easyrsa build-ca
		echo "Az easyrsa készen áll!"
		
	###################################################################################################
		#[GenCNF] mode	|	Mode 1.5
	###################################################################################################		
		
	elif [ "$1" = "-GenCNF" ]; then
	
		echo "CNF Generate mode is selected"
		echo ""
		
		# Check if the directory exists
		if [ ! -d "$CNF_DIR" ]; then
			echo "Warning!: The specified directory does not exist or is not a directory: $CNF_DIR"
			mkdir "$CNF_DIR"
			echo "Success!: The ${CNF_DIR} directory has been created!"
			echo ""
		fi
		
		if [ ! -f "$CNF_FILE" ]; then
			echo "Creating CNF file..."
			echo "organizationName = ${ORG_NAME}"
			echo "organizationalUnitName = ${ORG_UNIT}"
			echo "commonName = ${COMMON_NAME}"
			echo ""
			printf "[ default ]
SAN = DNS:${FQDN},IP:${IP_ADDRESS}
[ req ]
default_bits = 2048                        # RSA key size; change to 4096 if required by your organization
encrypt_key = no                           # Protect private key
default_md = sha256                        # MD to use
utf8 = yes                                 # Input is UTF-8
string_mask = utf8only                     # Emit UTF-8 strings
prompt = no                                # Prompt for DN
distinguished_name = server_dn             # DN template
req_extensions = server_reqext             # Desired extensions
[ server_dn ]
organizationName = ${ORG_NAME}
organizationalUnitName = ${ORG_UNIT}
commonName = ${COMMON_NAME}                 # Should match a listed SAN
[ server_reqext ]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier = hash
subjectAltName = \$ENV::SAN" > "${CNF_FILE}"
			echo "CNF file is ready!"
			echo "Warning: extendedKeyUsage = serverAuth,clientAuth"
			echo ""
		fi
		
	###################################################################################################
		#[GenCSR] mode	|	Mode 2
	###################################################################################################	
	
	elif [ "$1" = "-GenCSR" ]; then
	
		echo "CSR Generate mode is selected"
		echo ""
		
		if [ ! -d "$CNF_DIR" ]; then
			echo "Warning! The specified certificate directory does not exist or is not a directory: $CNF_DIR"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$CSR_DIR" ]; then
			echo "Warning! The specified certificate directory does not exist or is not a directory: $CSR_DIR"
			echo ""
			CREATE_DIR=true
		else
			CREATE_DIR=false
		fi

		if [ $CREATE_DIR == true ]; then
			echo "Create $CSR_DIR directory."
			mkdir "$CSR_DIR"
			echo "Success! $CSR_DIR directory is ready!"
			echo ""
		fi
			
		# Check if the directory exists
		if [ ! -d "$KEY_DIR" ]; then
			echo "Warning! The specified certificate directory does not exist or is not a directory: $KEY_DIR"
			echo ""
			CREATE_DIR=true
		else
			CREATE_DIR=false
		fi

		if [ $CREATE_DIR == true ]; then
			echo "Create $KEY_DIR directory."
			mkdir "$KEY_DIR"
			echo "Success! $KEY_DIR directory is ready!"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$COMPRESSED_FINAL_DIR" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: $COMPRESSED_FINAL_DIR"
			mkdir "$COMPRESSED_FINAL_DIR"
			echo "Success!: The ${COMPRESSED_FINAL_DIR} directory has been created!"
			echo ""
		fi
		
		for CLIENT_CNF_FILE in "$CNF_DIR"/*.cnf; do
		
			CLIENT_CERT_BASE=$(basename "$CLIENT_CNF_FILE" .cnf)
			
			CLIENT_CERT_FILE="${CERT_DIR}/${CLIENT_CERT_BASE}.crt"
			CLIENT_CSR_FILE="${CSR_DIR}/${CLIENT_CERT_BASE}.csr"
			CLIENT_KEY_FILE="${KEY_DIR}/${CLIENT_CERT_BASE}.key"

			## Generating CLIENT key
			echo "Generating key file: $CLIENT_KEY_FILE..."
			echo ""
			$OPENSSL_CMD genrsa -out "$CLIENT_KEY_FILE" 2048
			if [ $? -ne 0 ] ; then
				echo "ERROR: Key file ($CLIENT_KEY_FILE) generating is failed!"
				exit 1
			else
				echo "Success! KEY file: $CLIENT_KEY_FILE is ready!"
			fi

			## Generating CLIENT csr
			echo "Generating CSR file: $CLIENT_CSR_FILE..."
			echo ""
			$OPENSSL_CMD req -new -key "$CLIENT_KEY_FILE" -out "$CLIENT_CSR_FILE" -config "$CLIENT_CNF_FILE"
			if [ $? -ne 0 ] ; then
				echo "ERROR: CSR file ($CLIENT_CSR_FILE) generating is failed!"
				exit 1
			else
				echo "Success! CSR file: $CLIENT_CSR_FILE is ready!"
			fi
			
			# Create a directory for the compressed files
			echo ""
			echo "Compressing files in the current directory..."
			
			COMPRESSED_DIR="${COMPRESSED_FINAL_DIR}/${CLIENT_CERT_BASE}"
			mkdir "$COMPRESSED_DIR"

			#Copy $CLIENT_CSR_FILE to the compressed directory
			if [ -f "$CLIENT_CSR_FILE" ]; then
				cp "$CLIENT_CSR_FILE" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CLIENT_CSR_FILE successfully copied to $COMPRESSED_DIR."
				else
					echo "Failed to Copy $CLIENT_CSR_FILE to $COMPRESSED_DIR."
				fi
			else
				echo "$CLIENT_CSR_FILE cannot be found.."
			fi
			
			# Copy $CLIENT_KEY_FILE to the compressed directory
			if [ -f "$CLIENT_KEY_FILE" ]; then
				cp "$CLIENT_KEY_FILE" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CLIENT_KEY_FILE successfully copied to $COMPRESSED_DIR."
				else
					echo "Failed to Copy $CLIENT_KEY_FILE to $COMPRESSED_DIR."
				fi
			else
				echo "$CLIENT_KEY_FILE cannot be found.."
			fi
			
			# Compress the directory
			tar -czvf "$COMPRESSED_DIR.tar.gz" "$COMPRESSED_DIR"
			if [ $? -eq 0 ]; then
				echo "$COMPRESSED_DIR successfully compressed."
			else
				echo "Failed to compress $COMPRESSED_DIR."
			fi
			
		done
	
	###################################################################################################
		#[GenCert] mode	|	Mode 3
	###################################################################################################	
	
	elif [ "$1" = "-GenCert" ]; then
		echo "####################"
		echo "Cert generate with EasyRSA mode is selected"
		echo ""
		
		# Check if the directory exists
		if [ ! -d "$CERT_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $CERT_DIR"
			mkdir "$CERT_DIR"
			echo "Success!: The ${CERT_DIR} directory has been created!"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$CA_CERT_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $CA_CERT_DIR"
			mkdir "$CA_CERT_DIR"
			echo "Success!: The ${CA_CERT_DIR} directory has been created!"
			echo ""
		fi
		
		read -sp "Enter the CA password: " CA_PASSWORD
		echo ""
		printf "%s" "$CA_PASSWORD" > ${SOURCE_DIR}/ca_pass.txt

		
		# Végigmegyünk a csr fájlokon a megadott mappában
		for CSR_FILE in "${CSR_DIR}"/*.csr; do

			# Az easyrsa import-req parancs használata a PKI mappában lévő CA-val
			echo "Import the request to the easyrsa CA"
			
			CSR_BASENAME=$(basename "${CSR_FILE}" .csr)
			
			cd $EASYRSA_DIR
			./easyrsa import-req "${CSR_FILE}" "${CSR_BASENAME}" --batch
			if [ $? -ne 0 ] ; then
					echo "Warning: Import failed!"
				#exit 1
				else
					echo "Success! ${CSR_BASENAME} is imported!"
				fi
			
			##Sign the req
			echo "Sign the request as a client cert"
			./easyrsa --batch --passin=file:${SOURCE_DIR}/ca_pass.txt sign-req client "${CSR_BASENAME}"
			if [ $? -ne 0 ] ; then
					echo "ERROR: The signature failed!"
				#exit 1
				else	
					echo "Success! The ${CSR_BASENAME} crt file is ready!"
				fi
			
			#copy certs to cert folder for Import mode
			cp "${EASYRSA_DIR}/pki/issued/${CSR_BASENAME}.crt" "${CERT_DIR}"
			if [ $? -ne 0 ] ; then
					echo "Error: Copy has been failed!"
				else
					echo "Success! The ${CSR_BASENAME}.crt file has been copied."
				fi
				
			cp "${EASYRSA_DIR}/pki/ca.crt" "${CA_CERT_DIR}"
			if [ $? -ne 0 ] ; then
					echo "Error: Copy has been failed!"
				else
					echo "Success! The ca.crt file has been copied."
				fi
		done
		
		rm -f ${SOURCE_DIR}/ca_pass.txt
		#Törlés a history-ból
				if [[ -n "$CA_PASSWORD" ]]; then
				#Eltávolítjuk az összes olyan sort a history-ból, amely tartalmazza a jelszót
					history | grep "$CA_PASSWORD" | cut -d" " -f2- | while read -r line; do
						history -d "$line"
					done

				#Törlés a változóból
					unset CA_PASSWORD
					echo ""
					echo "CA Password has been deleted from history"
					echo ""
				fi

	###################################################################################################
		#[Import] mode 	|	Mode 4
	###################################################################################################
	
	elif [ "$1" = "-Import" ]; then
		echo "####################"
		echo "Import mode selected"
		echo ""
		
		#One password for all p12 file
		read -sp "Enter password for pkcs12 file: " PKCS12_PASSWORD
		echo ""
		
		# Check if the directory exists
		if [ ! -d "$CERT_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $CERT_DIR"
			echo ""
			exit 1
		fi
		
		# Check if the directory exists
		if [ ! -d "$CA_CERT_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $CA_CERT_DIR"
			echo ""
			exit 1
		fi
		
		# Check if the directory exists
		if [ ! -d "$KEY_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $KEY_DIR"
			echo ""
			exit 1
		fi
		
		# Check if the directory exists
		if [ ! -d "$INTERMEDIATE_CA_DIR" ]; then
			echo "The specified certificate directory does not exist or is not a directory: $INTERMEDIATE_CA_DIR"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$COMPRESSED_FINAL_DIR" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: $COMPRESSED_FINAL_DIR"
			mkdir "$COMPRESSED_FINAL_DIR"
			echo "Success!: The ${COMPRESSED_FINAL_DIR} directory has been created!"
			echo ""
		fi
		
		for CLIENT_CERT_FILE in "$CERT_DIR"/*.crt; do
			if [ -f "$CLIENT_CERT_FILE" ]; then
				
				echo ""
				echo "###New Round###"
				echo ""
				
				CLIENT_CERT_BASE=$(basename "$CLIENT_CERT_FILE" .crt)
				echo "A cert base fájl neve: $CLIENT_CERT_BASE"
				
				# Read the client private key file name from the certificate directory
				CLIENT_KEY_FILE="$KEY_DIR/$CLIENT_CERT_BASE.key"
				if [ ! -f "$CLIENT_KEY_FILE" ]; then
					echo "No client-private.key file found for certificate $CLIENT_CERT_BASE"
					echo ""
					exit 1
				else
					echo "A client key neve: $CLIENT_KEY_FILE"
				fi
				
				# Read the intermediateCA cert file name from the certificate directory
				INTERMEDIATE_CA_FILE="$INTERMEDIATE_CA_DIR/${CLIENT_CERT_BASE}.crt"
				if [ ! -f "$INTERMEDIATE_CA_FILE" ]; then
					echo "Warning! No intermediateCA .crt file found in the specified certificate directory: $INTERMEDIATE_CA_DIR"
					echo ""
					#exit 1
				else
					echo "Az ICA neve: $INTERMEDIATE_CA_FILE"
				fi
				
				# Read the rootCA file name from the certificate directory
				#ROOT_CA_FILE="$CA_CERT_DIR/${CLIENT_CERT_BASE}_CA.crt"		//ha más lenne a root ca neve
				ROOT_CA_FILE="$CA_CERT_DIR/ca.crt"
				if [ ! -f "$ROOT_CA_FILE" ]; then
					echo "No rootCA.key file found in the specified certificate directory: $CA_CERT_DIR"
					echo ""
					exit 1
				else
					echo "A rootCA File neve: $ROOT_CA_FILE"
				fi
				
				# Do the rest of the operations with the files here...
					# Concatenate the client cert and rootCA files to create a .pem file
				CLIENT_CERT_PEM="${CLIENT_CERT_BASE}.pem"
				if [ -f "$INTERMEDIATE_CA_FILE" ]; then
					echo "There is a INTERMEDIATE_CA file!"
					$CAT_CMD "$CLIENT_CERT_FILE" "$INTERMEDIATE_CA_FILE" "$ROOT_CA_FILE" >"$CLIENT_CERT_PEM"
				else
					echo "There is no INTERMEDIATE_CA file!"
					$CAT_CMD "$CLIENT_CERT_FILE" "$ROOT_CA_FILE" >"$CLIENT_CERT_PEM"
				fi
				if [ $? -ne 0 ] ; then
					echo ""
					echo "ERROR: Concatenation has failed!"
					echo ""
					else
						echo "Success! Created $CLIENT_CERT_PEM"
					fi

				# Create a .der file from the client key in the .pem file
				CLIENT_KEY_DER="${CLIENT_CERT_BASE}-DER.key"
				#$OPENSSL_CMD pkcs8 -topk8 -inform PEM -outform DER -in "$CLIENT_CERT_PEM" -out "$CLIENT_KEY_DER" -nocrypt
				$OPENSSL_CMD pkcs8 -topk8 -inform PEM -outform DER -in "$CLIENT_KEY_FILE" -out "$CLIENT_KEY_DER" -nocrypt
				if [ $? -ne 0 ] ; then
					echo "ERROR: Could not create the $CLIENT_KEY_DER file!"
					echo ""
					else
						echo "Success! Created $CLIENT_KEY_DER"
					fi

				# Generate a .p12 file from the .pem and .der files
				CLIENT_P12_FILE="${CLIENT_CERT_BASE}.p12"
				$OPENSSL_CMD pkcs12 -export -in "$CLIENT_CERT_PEM" -inkey "$CLIENT_KEY_FILE" -name "syslog-tls" -out "$CLIENT_P12_FILE" -passout "pass:$PKCS12_PASSWORD"
				if [ $? -ne 0 ] ; then
					echo "ERROR: Could not create the $CLIENT_P12_FILE file!"
					echo ""
					else
						echo "Success! Created $CLIENT_P12_FILE"
						echo ""
					fi
			#fi
			
			##Itt jön az a rész, hogy a cert base név és majd certet megkapó host neve ugyanaz és akkor simán átmásolja a fájlokat a script.
			echo "Sending the files to the final place..."
			HOSTNAME_FOUND=$(grep -w "${CLIENT_CERT_BASE}" /etc/hosts)
			if [ -n "${HOSTNAME_FOUND}" ]; then
				
				#$ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -p "forras_file" "${QRADAR_DIR}"
				$ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -p "${CLIENT_CERT_PEM}" -r "${QRADAR_DIR}"
				if [ $? -ne 0 ] ; then
					echo "ERROR: Could not send the ${CLIENT_CERT_PEM} file!"
				else
					echo "Success! The ${CLIENT_CERT_PEM} file has been sent to ${QRADAR_DIR}."
				fi
				
				$ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -p "${CLIENT_KEY_FILE}" -r "${QRADAR_DIR}"
				if [ $? -ne 0 ] ; then
					echo "ERROR: Could not send the ${CLIENT_KEY_FILE} file!"
				else
					echo "Success! The ${CLIENT_KEY_FILE} file has been sent to ${QRADAR_DIR}."
				fi
				
				if $ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -p "${CLIENT_P12_FILE}" -r "${QRADAR_DIR}" ; then
					echo "Success! The ${CLIENT_P12_FILE} file has been sent to ${QRADAR_DIR}."
				else
					echo "ERROR: Failed to send the ${CLIENT_P12_FILE} file to ${QRADAR_DIR}!"
				fi
				
				# # Deleting old keystore and import the new one.
				# if $ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -c "rm -f ${DEST_KEY_DIR}/syslog-tls.keystore" && $ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -c "keytool -importkeystore -destkeystore ${DEST_KEY_DIR}/syslog-tls.keystore -deststorepass syslog-tls -srcstoretype PKCS12 -srckeystore ${QRADAR_DIR}/${CLIENT_P12_FILE} -alias $KEYTOOL_ALIAS" ; then
					 # echo "Success! The ${CLIENT_P12_FILE} file has been imported to syslog-tls.keystore."
				# else
					 # echo "ERROR: Failed to import the ${CLIENT_P12_FILE} file to syslog-tls.keystore!"
				# fi

				# #restart service
				# if $ALL_SERVER_CMD -n "${CLIENT_CERT_BASE}" -c "systemctl restart ecs-ec-ingress" ; then
					# echo "'ecs-ec-ingress' service restarted successfully."
				# else
					# echo "ERROR: Failed to restart 'ecs-ec-ingress' service!"
				# fi
			else
				echo "The transfer of the files failed. The hostname: "${CLIENT_CERT_BASE}" is not found or is not correct inside the /etc/hosts file."
			fi
			
			#Endgame
			#Deleting files from current dir
			echo ""
			echo "Compressing files in the current directory..."

			# Create a directory for the compressed files
			COMPRESSED_DIR="${COMPRESSED_FINAL_DIR}/${CLIENT_CERT_BASE}"
			mkdir "$COMPRESSED_DIR"

			# Move $CLIENT_P12_FILE to the compressed directory
			if [ -f "$CLIENT_P12_FILE" ]; then
				mv "$CLIENT_P12_FILE" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CLIENT_P12_FILE successfully moved to $COMPRESSED_DIR."
				else
					echo "Failed to Move $CLIENT_P12_FILE to $COMPRESSED_DIR."
				fi
			else
				echo "$CLIENT_P12_FILE cannot be found.."
			fi

			# Move $CLIENT_CERT_PEM to the compressed directory
			if [ -f "$CLIENT_CERT_PEM" ]; then
				mv "$CLIENT_CERT_PEM" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CLIENT_CERT_PEM successfully moved to $COMPRESSED_DIR."
				else
					echo "Failed to Move $CLIENT_CERT_PEM to $COMPRESSED_DIR."
				fi
			else
				echo "$CLIENT_CERT_PEM cannot be found.."
			fi

			# Move $CLIENT_KEY_DER to the compressed directory
			if [ -f "$CLIENT_KEY_DER" ]; then
				mv "$CLIENT_KEY_DER" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CLIENT_KEY_DER successfully moved to $COMPRESSED_DIR."
				else
					echo "Failed to Move $CLIENT_KEY_DER to $COMPRESSED_DIR."
				fi
			else
				echo "$CLIENT_KEY_DER cannot be found.."
			fi

			# Move $CLIENT_CSR_FILE to the compressed directory
			CLIENT_CSR_FILE="${CLIENT_CERT_BASE}.csr"
			if [ -f "$CSR_DIR/${CLIENT_CSR_FILE}" ]; then
				mv "$CSR_DIR/${CLIENT_CSR_FILE}" "$COMPRESSED_DIR/"
				if [ $? -eq 0 ]; then
					echo "$CSR_DIR/${CLIENT_CSR_FILE} successfully moved to $COMPRESSED_DIR."
				else
					echo "Failed to Move $CSR_DIR/${CLIENT_CSR_FILE} to $COMPRESSED_DIR."
				fi
			else
				echo "$CSR_DIR/${CLIENT_CSR_FILE} cannot be found.."
			fi

			# Compress the directory
			tar -czvf "$COMPRESSED_DIR.tar.gz" "$COMPRESSED_DIR"
			if [ $? -eq 0 ]; then
				echo "$COMPRESSED_DIR successfully compressed."
			else
				echo "Failed to compress $COMPRESSED_DIR."
			fi

			# Remove the uncompressed directory
			#rm -r "$COMPRESSED_DIR"
			#echo "Uncompressed directory $COMPRESSED_DIR deleted."
		fi
		done
		
		# Törlés a history-ból
				if [[ -n "$PKCS12_PASSWORD" ]]; then
				#Eltávolítjuk az összes olyan sort a history-ból, amely tartalmazza a jelszót
					history | grep "$PKCS12_PASSWORD" | cut -d" " -f2- | while read -r line; do
						history -d "$line"
					done

				#Törlés a változóból
					unset PKCS12_PASSWORD
					echo "P12 Password has been deleted from history"
					echo ""
				fi
				
		echo "It's all done!"
		echo ""
		
	###################################################################################################
		#[DLCImport] mode 	|	Mode 5
	###################################################################################################
	
	elif [ "$1" = "-DLCImport" ]; then
		echo "####################"
		echo "DLCImport mode selected"
		# echo "Note: If CNF file is necessary and it is missing: -GenCNF"
		# echo "Note: If CSR and Private key are missing: -GenCSR"
		echo "Note: Required root cert files: CA.crt + root_int_CA.crt"
		echo ""
		
		# Check if the directory exists
		if [ ! -d "$KEY_DIR" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: $KEY_DIR"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$CA_CERT_DIR" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: $CA_CERT_DIR"
			echo ""
		fi
		
		# Check if Client ROOT CA cert exists and copy to the anchors dir.
		if [ ! -f "$CLIENT_ROOT_CA" ]; then
			echo "Error!: Client root cert is missing!"
			exit 1
		else
			cp "${CLIENT_ROOT_CA}" "${ANCHORS}"
			echo "The ${CLIENT_ROOT_CA} file copied to ${ANCHORS}"
			echo ""
		fi
		
		# Check if the directory exists
		if [ ! -d "$KEY_STORES" ]; then
			echo "Warning! The specified certificate directory does not exist or is not a directory: $KEY_STORES"
			mkdir "$KEY_STORES"
			echo "Success!: The ${KEY_STORES} directory has been created!"
			echo ""
		fi
		
		#PKCS12 Password
		read -sp "Enter password for pkcs12 file: " PKCS12_PASSWORD
		echo ""
		
		#If you're using your own truststore... #Import keystore 
		if [ -f "$CLIENT_ROOT_CA" ]; then
			echo "Client root CA: $CLIENT_ROOT_CA"
			$KEYTOOL_CMD -import -alias "${KEYSTORE_ROOT_ALIAS_NAME}" -file "${CLIENT_ROOT_CA}" -keystore "${KEYSTORE_NAME}"
			if [ $? -eq 0 ]; then
				echo "Success! Root CA has been imported!"
			else
				echo "Error! Failed to import root CA cert to keystore."
				exit 1
			fi
		else
			echo "Warning! No client rootCA.crt file found in the specified certificate directory: $CA_CERT_DIR"
			echo ""
			
		fi
		
		#If you're using your own truststore... #Import keystore 
		if [ -f "$CLIENT_INT_CA" ]; then
			echo "Client intermediateCA: $CLIENT_INT_CA"
			$KEYTOOL_CMD -import -alias "${KEYSTORE_INT_ALIAS_NAME}" -file "${CLIENT_INT_CA}" -keystore "${KEYSTORE_NAME}"
			if [ $? -eq 0 ]; then
				echo "Success! Root intermediateCA has been imported!"
			else
				echo "Error! Failed to import root intermediateCA cert to keystore."
				exit 1
			fi
		else
			echo "Warning! No client intermediateCA .crt file found in the specified certificate directory: $INTERMEDIATE_CA_DIR"
			echo ""
		fi
		
		#Copy trust store file to /opt/qradar/conf/key_stores dir
		mv "${KEYSTORE_NAME}" "${KEY_STORES}"
		if [ $? -eq 0 ]; then
			echo "${KEYSTORE_NAME} trust store file successfully moved to $KEY_STORES."
			echo ""
		else
			echo "Failed copy ${KEYSTORE_NAME} trust store file to ${KEY_STORES}."
			exit 1
		fi
		
		#If you're using the default truststore...
		update-ca-trust
		
		#If the CLIENT certificate is in DER (binary) format, convert it to PEM format	|| Ha a .crt der formátumu akkor átkonvertálja pem-mé és akkor már a client pemmel dolgozik később. Ha viszont a .crt alapból PEM formátumu, nem konvertál és később alapból a crtvel dolgozik.
		if [ -f "${CLIENT_CERT_CRT}" ]; then 
			#$OPENSSL_CMD x509 -inform der -in "${CLIENT_CERT_CRT}" >/dev/null 2>&1			#az " -inform der " eredetileg szerepelne a parancsban, de hibát dob ki a konvertálásnál
			$OPENSSL_CMD x509 -in "${CLIENT_CERT_CRT}" >/dev/null 2>&1
			echo "The ${CLIENT_CERT_CRT} is in DER format."
			echo "Converting cert file to PEM format."
			$OPENSSL_CMD x509 -in "${CLIENT_CERT_CRT}" -out "${CLIENT_CERT_PEM}"
			echo "${CLIENT_CERT_PEM} is ready!"
			echo ""
		else
			echo "The ${CLIENT_CERT_CRT} is in PEM format."
			echo ""
		fi
		
		#If the CLIENT intermediateCA certificate is in DER (binary) format, convert it to PEM format	|| Ha a .crt der formátumu akkor átkonvertálja pem-mé és akkor már a client pemmel dolgozik később. Ha viszont a .crt alapból PEM formátumu, nem konvertál és később alapból a crtvel dolgozik.
		if [ -f "${INT_CA_CRT_FILE}" ]; then 
			$OPENSSL_CMD x509 -in "${INT_CA_CRT_FILE}" >/dev/null 2>&1
			echo "The ${INT_CA_CRT_FILE} is in DER format."
			echo "Converting cert file to PEM format."
			$OPENSSL_CMD x509 -in "${INT_CA_CRT_FILE}" -out "${INT_CA_PEM_FILE}"
			echo "${INT_CA_PEM_FILE} is ready!"
		else
			echo "The ${INT_CA_CRT_FILE} is in PEM format."
		fi
		
		#Append the intermediate CA certificate to the signed server certificate
		if [ -f "${INT_CA_PEM_FILE}" ] && [ -f "${CLIENT_CERT_PEM}" ]; then 
			$CAT_CMD "${INT_CA_PEM_FILE}" >> "${CLIENT_CERT_PEM}"
			echo "Az Intermediate CA .pem fájl hozzá lett adva az aláírt szerver cert (.pem) fájlhoz."
		elif [ -f "${INT_CA_PEM_FILE}" ] && [ -f "${CLIENT_CERT_CRT}" ]; then 
			$CAT_CMD "${INT_CA_PEM_FILE}" >> "${CLIENT_CERT_CRT}"
			echo "Az Intermediate CA .pem fájl hozzá lett adva az aláírt szerver cert (.crt) fájlhoz."
		elif [ -f "${INT_CA_CRT_FILE}" ] && [ -f "${CLIENT_CERT_PEM}" ]; then 
			$CAT_CMD "${INT_CA_CRT_FILE}" >> "${CLIENT_CERT_PEM}"
			echo "Az Intermediate CA cert fájl hozzá lett adva az aláírt szerver cert (.pem) fájlhoz."
		elif [ -f "${INT_CA_CRT_FILE}" ] && [ -f "${CLIENT_CERT_CRT}" ]; then 
			$CAT_CMD "${INT_CA_CRT_FILE}" >> "${CLIENT_CERT_CRT}"
			echo "Az Intermediate CA cert fájl hozzá lett adva az aláírt szerver cert (.crt) fájlhoz."
		else
			echo "Warning! There is no intermediate CA, so the append cannot succeed."
		fi
		
		#If the store server certificate that you received is not in PKCS#12 format, convert the client certificate to PKCS#12 format. 
					#Ne tévesszen meg senkit! A DER -> PEM konvertálás megtörtént, elsőnek a PEM fájlt veszi alább figyelembe, ha viszont az alapból beadott .crt fájl PEM formátumban van, akkor nincs .pem fájl, így az elif lép érvénybe.
		if [ -f "${KEY_FILE}" ] && [ -f "${CLIENT_CERT_PEM}" ]; then 
			$OPENSSL_CMD pkcs12 -inkey "${KEY_FILE}" -in "${CLIENT_CERT_PEM}" -export -out "${DLC_P12_FILE}" -passout "pass:$PKCS12_PASSWORD"
			echo "A p12 file: [${DLC_P12_FILE}] is ready!"
		elif [ -f "${KEY_FILE}" ] && [ -f "${CLIENT_CERT_CRT}" ]; then 
			$OPENSSL_CMD pkcs12 -inkey "${KEY_FILE}" -in "${CLIENT_CERT_CRT}" -export -out "${DLC_P12_FILE}" -passout "pass:$PKCS12_PASSWORD"
			echo "A p12 file: [${DLC_P12_FILE}] is ready!"
			echo ""
		else
			echo "Error! Missing some file (.key or .pem/crt)."
			exit 1
		fi
			
		#Copy the dlc-server.pfx file to the /opt/qradar/conf/key_stores directory.
		if [ ! -f "$DLC_P12_FILE" ]; then
			echo "Warning! ${DLC_P12_FILE} is cannot be found!"
			exit 1
		else
			cp "${DLC_P12_FILE}" "${KEY_STORES}"
			echo "${DLC_P12_FILE} is copied to ${KEY_STORES}."
		fi
		
		## Create a directory for the compressed files
		echo ""
		echo "Compressing files in the current directory..."
		
		# Check if the directory exists
		if [ ! -d "${COMPRESSED_FINAL_DIR}" ]; then
			echo "Warning!: The specified certificate directory does not exist or is not a directory: ${COMPRESSED_FINAL_DIR}"
			mkdir "${COMPRESSED_FINAL_DIR}"
			echo ""
		fi
		
		COMPRESSED_DIR="${COMPRESSED_FINAL_DIR}/${FQDN}"
		mkdir "$COMPRESSED_DIR"
		
		# Move $CLIENT_ROOT_CA to the compressed directory
		if [ -f "$CLIENT_ROOT_CA" ]; then
			mv "$CLIENT_ROOT_CA" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$CLIENT_ROOT_CA successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $CLIENT_ROOT_CA to $COMPRESSED_DIR."
			fi
		else
			echo "$CLIENT_ROOT_CA cannot be found.."
		fi
		
		# Move $CLIENT_INT_CA to the compressed directory
		if [ -f "$CLIENT_INT_CA" ]; then
			mv "$CLIENT_INT_CA" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$CLIENT_INT_CA successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $CLIENT_INT_CA to $COMPRESSED_DIR."
			fi
		else
			echo "$CLIENT_INT_CA cannot be found.."
		fi
		
		#Move $CSR_FILE to the compressed directory
		if [ -f "$CSR_FILE" ]; then
			mv "$CSR_FILE" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$CSR_FILE successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $CSR_FILE to $COMPRESSED_DIR."
			fi
		else
			echo "$CSR_FILE cannot be found.."
		fi
		
		# Move $KEY_FILE to the compressed directory
		if [ -f "$KEY_FILE" ]; then
			mv "$KEY_FILE" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$KEY_FILE successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $KEY_FILE to $COMPRESSED_DIR."
			fi
		else
			echo "$KEY_FILE cannot be found.."
		fi
		
		# Move $CLIENT_CERT_PEM to the compressed directory
		if [ -f "$CLIENT_CERT_PEM" ]; then
			mv "$CLIENT_CERT_PEM" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$CLIENT_CERT_PEM successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $CLIENT_CERT_PEM to $COMPRESSED_DIR."
			fi
		else
			echo "$CLIENT_CERT_PEM cannot be found.."
		fi
		
		# Move $INT_CA_CRT_FILE to the compressed directory
		if [ -f "$INT_CA_CRT_FILE" ]; then
			mv "$INT_CA_CRT_FILE" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$INT_CA_CRT_FILE successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $INT_CA_CRT_FILE to $COMPRESSED_DIR."
			fi
		else
			echo "$INT_CA_CRT_FILE cannot be found.."
		fi

		# Move $INT_CA_PEM_FILE to the compressed directory
		if [ -f "$INT_CA_PEM_FILE" ]; then
			mv "$INT_CA_PEM_FILE" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$INT_CA_PEM_FILE successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $INT_CA_PEM_FILE to $COMPRESSED_DIR."
			fi
		else
			echo "$INT_CA_PEM_FILE cannot be found.."
		fi
		
		# Move $DLC_P12_FILE to the compressed directory
		if [ -f "$DLC_P12_FILE" ]; then
			mv "$DLC_P12_FILE" "$COMPRESSED_DIR/"
			if [ $? -eq 0 ]; then
				echo "$DLC_P12_FILE successfully moved to $COMPRESSED_DIR."
			else
				echo "Failed to Move $DLC_P12_FILE to $COMPRESSED_DIR."
			fi
		else
			echo "$DLC_P12_FILE cannot be found.."
		fi
		
		# Compress the directory
		tar -czvf "$COMPRESSED_DIR.tar.gz" "$COMPRESSED_DIR"
		if [ $? -eq 0 ]; then
			echo "$COMPRESSED_DIR successfully compressed."
		else
			echo "Failed to compress $COMPRESSED_DIR."
		fi
		
		# Törlés a history-ból
		if [[ -n "$PKCS12_PASSWORD" ]]; then
		#Eltávolítjuk az összes olyan sort a history-ból, amely tartalmazza a jelszót
			history | grep "$PKCS12_PASSWORD" | cut -d" " -f2- | while read -r line; do
				history -d "$line"
			done

		#Törlés a változóból
			unset PKCS12_PASSWORD
			echo ""
			echo "P12 Password has been deleted from history"
			echo ""
		fi
		
	fi #ez a nagy egészet lezáró!
