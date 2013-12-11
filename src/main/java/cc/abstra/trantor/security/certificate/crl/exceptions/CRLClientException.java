/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
 *
 * Licencia con arreglo a la EUPL, Versión 1.1 o –en cuanto sean aprobadas por la Comisión Europea– versiones posteriores de la EUPL (la Licencia);
 * Solo podrá usarse esta obra si se respeta la Licencia.
 *
 * Puede obtenerse una copia de la Licencia en:
 *
 * http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
 *
 * Salvo cuando lo exija la legislación aplicable o se acuerde por escrito, el programa distribuido con arreglo a la Licencia se distribuye «TAL CUAL»,
 * SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * Véase la Licencia en el idioma concreto que rige los permisos y limitaciones que establece la Licencia.
 */
package cc.abstra.trantor.security.certificate.crl.exceptions;

/**
 * Excepción OCSP
 */
public class CRLClientException extends Exception {

	/**
	 * Clase encargada tratar los errores producidos en la validacion OCSP
	 *
	 */
	public CRLClientException() {
		super();
	}

	/**
	 * @param message
	 */
	public CRLClientException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public CRLClientException(Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public CRLClientException(String message, Throwable cause) {
		super(message, cause);
	}

}
