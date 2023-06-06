#!/bin/bash

#Tutorial:
#-GenCSR: Generál egy előre megadott CNF fájl alapján egy privát kulcsot és hozzá egy CSR fájlt, amit aztán majd alá kell írni.
#-Import: a már aláírt (visszakapott) cert(ek) alapján generál egy .pem, .p12, -DER.key fájlt, majd ha ugyanaz a cert base név és ami az etc/hosts-ban is megvan adva, a fájlok az "all_server.sh" scriptet használva, kiosztásra kerülnek.

#FONTOS: minden fájlnak ('.crt', '.key, '_CA.crt' és esetleg az intermediateCA ami szintén ".crt" csak külön mappában), ugyanaz kell legyen a nevük! ['teszt.crt', 'teszt.key, 'teszt_CA.crt']

########
#Innen olvassa fel a certeket (signed xy.crt & CA.key & intermediateCA.crt).
CA_CERT_DIR="$(pwd)/ca"
CERT_DIR="$(pwd)/cert"
INTERMEDIATE_CA_DIR="$(pwd)/intermediateCA"
########

OPENSSL_CMD="/usr/bin/openssl"
CAT_CMD="/usr/bin/cat"
ALL_SERVER_CMD="/opt/qradar/support/all_servers.sh"

#Innen olvassa fel a .CNF fájlt a CSR Fájl generáláshoz.
CNF_DIR="$(pwd)/cnf"

#Ide kerül mentésre .csr és a private key.
CSR_DIR="$(pwd)/csr"
KEY_DIR="$(pwd)/key"

#Ide kerülnek majd az elkészült fájlok backup gyanánt. Sima mappába és tömörített verzióban is.
COMPRESSED_FINAL_DIR="$(pwd)/compressed_final"

#Végén ebbe a mappába kerül majd az újonnan generált fájlok hada (.pem, .der, .p12).
#QRADAR_DIR="/opt/qradar/conf/trusted_certificates/"
#QRADAR_DIR="/tmp/kliens/tteszt/0504/final"
QRADAR_DIR="/tmp/teszt"

#Keytool
DEST_KEY_DIR="/opt/qradar/conf/"
KEYTOOL_ALIAS="syslog-tls"

	if [[ $# -eq 0 ]]; then
		echo "Usage: $0 [-GenCSR] [-Import]"
	exit 1
	fi

	###################################################################################################
		#[GenCSR] mode	|	Mode 1
	###################################################################################################

	if [[ "$1" == "-GenCSR" ]]; then
		echo "CSR Generate mode selected"
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
		
		
		for CLIENT_CNF_FILE in "$CNF_DIR"/*.cnf; do
		
			CLIENT_CERT_FILE="$CERT_DIR/$(basename ${CLIENT_CNF_FILE%.cnf}).crt"
			CLIENT_CSR_FILE="$CSR_DIR/$(basename ${CLIENT_CNF_FILE%.cnf}).csr"
			CLIENT_KEY_FILE="$KEY_DIR/$(basename ${CLIENT_CNF_FILE%.cnf}).key"

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
		done

	###################################################################################################
		#[Import] mode 	|	Mode 2
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
		
	fi #ez a nagy egészet lezáró!