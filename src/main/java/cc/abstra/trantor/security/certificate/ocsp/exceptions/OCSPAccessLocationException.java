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
package cc.abstra.trantor.security.certificate.ocsp.exceptions;


/**
 * Clase encargada tratar los errores producidos al conectarse al servidor OCSP
 *
 */

public class OCSPAccessLocationException extends OCSPException {

	public OCSPAccessLocationException() {
		super();
	}

	/**
	 * Constructor de la clase OCSPAccessLocationException
	 * @param mensaje
	 */
	public OCSPAccessLocationException(String mensaje) {
		  super(mensaje);
	}

	/**
	 * Constructor de la clase OCSPAccessLocationException
	 * @param causa
	 */
	public OCSPAccessLocationException(Throwable causa) {
		super(causa);
	}

	/**
	 * Constructor de la clase OCSPAccessLocationException
	 * @param mensaje
	 * @param causa
	 */
	public OCSPAccessLocationException(String mensaje, Throwable causa) {
		super(mensaje, causa);
	}
}
