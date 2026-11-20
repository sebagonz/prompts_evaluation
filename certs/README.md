# Certificados de confianza del laboratorio

`kyndryl-ssl-inspection.crt` es la CA **pública** de inspección TLS ya utilizada
en `giskard-poc/ollama`. El Dockerfile instala los `.crt` de este directorio
con `update-ca-certificates` antes de descargar dependencias. No contiene
claves privadas. Para otra red, reemplazar esta CA por las CA aprobadas por
ese ambiente antes del build. La validación TLS de pip permanece habilitada.
