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
package cc.abstra.trantor.security.certificate.ocsp;

import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPClientException;
import cc.abstra.trantor.security.certificate.ocsp.exceptions.OCSPProxyException;
import cc.abstra.trantor.security.ssl.ISSLManager;
import cc.abstra.trantor.security.ssl.OwnSSLProtocolSocketFactory;
import cc.abstra.trantor.security.utils.Base64Coder;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.ocsp.*;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class OCSPClient {

	/** 5000 */
    private static final Integer INT_20000 = new Integer(20000);

    private Integer timeOut = INT_20000;

	private String 	servidorURL;

    static Log log = LogFactory.getLog(OCSPClient.class);

    private PostMethod method = null;
    private HttpClient client = null;

    /**
     * Constructor de la clase OCSPCliente
     * @param servidorURL Servidor URL
     */
    public OCSPClient(String servidorURL) {
        this.servidorURL = servidorURL;
        //if (servidorURL.startsWith("https://"))
        //    this.ssl = true;
    }


    /**
     * Este método valida el Certificado contra un servidor OCSP
     * @param certificadoUsuario Certificado
     * @param certificadoEmisor Certificado del emisor. En el caso de un certificado autofirmado el certificado del emisor será el mismo que el del usuario
     * @return OCSPResponse tipo número de respuesta y mensaje correspondiente
     * @throws OCSPClientException Errores del cliente OCSP
     */
    public OCSPResponse validateCert(X509Certificate certificadoUsuario, X509Certificate certificadoEmisor) throws OCSPClientException, OCSPProxyException {

    	OCSPResponse respuesta = new OCSPResponse();

        OCSPReqGenerator generadorPeticion = new OCSPReqGenerator();
        OCSPReq peticionOCSP = null;
        OCSPResp OCSPResponse = null;
        CertificateID certificadoId = null;
                
        try {
            certificadoId = new CertificateID(CertificateID.HASH_SHA1, certificadoEmisor, certificadoUsuario.getSerialNumber());
            log.info(OCSPConstants.MENSAJE_CREADO_INDENTIFICADO);
        } catch (OCSPException e) {
            log.info( OCSPConstants.MENSAJE_ERROR_GENERAR_IDENTIFICADOR + e.getMessage());
            throw new OCSPClientException(OCSPConstants.LIBRERIA_OCSP_ERROR_2 + OCSPConstants.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        generadorPeticion.addRequest(certificadoId);

        try {
            peticionOCSP = generadorPeticion.generate();
            log.info(OCSPConstants.MENSAJE_PETICION_OCSP_GENERADA);
        }
        catch (OCSPException e) {
            log.error( OCSPConstants.ERROR_MENSAJE_GENERAR_PETICION_OCSP + e.getMessage());
            throw new OCSPClientException(OCSPConstants.LIBRERIA_OCSP_ERROR_3 + OCSPConstants.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        
        client = new HttpClient();

        client.getParams().setParameter(HttpClientParams.SO_TIMEOUT, timeOut);
        client.getParams().setParameter(HttpClientParams.RETRY_HANDLER,
        		new DefaultHttpMethodRetryHandler(0, false));

        method = new PostMethod(servidorURL);

        method.addRequestHeader(OCSPConstants.CONTENT_TYPE, OCSPConstants.APPLICATION_OCSP_REQUEST);
        ByteArrayInputStream datos = null;

        try {
        	datos = new ByteArrayInputStream(peticionOCSP.getEncoded());
        } catch (IOException e) {
        	log.error( OCSPConstants.MENSAJE_ERROR_LEER_PETICION + e.getMessage());
        	throw new OCSPClientException(OCSPConstants.LIBRERIA_OCSP_ERROR_4 + OCSPConstants.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        InputStreamRequestEntity rq = new InputStreamRequestEntity (datos);
        method.setRequestEntity(rq);

        method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
        		new DefaultHttpMethodRetryHandler(0, false));
        method.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, timeOut);

        MethodThread ocspThread =  new MethodThread();
        ocspThread.start();

        try {
        	try {
        		ocspThread.join(timeOut);
        	} catch (InterruptedException e) {
        		method.abort();
            	log.error( OCSPConstants.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + "Demanda de interrupción");
        		retryPost(0, peticionOCSP, ocspThread, datos.available());
        	}

        	int estadoCodigo = ocspThread.getResult();//cliente.executeMethod(metodo);
        	log.info(OCSPConstants.MENSAJE_PETICION_ENVIADA);

        	if (estadoCodigo != HttpStatus.SC_OK) {
        		if (log.isDebugEnabled()) {
        			log.debug("Respuesta de error: " + estadoCodigo);
        		}
        		retryPost(estadoCodigo, peticionOCSP, ocspThread, datos.available());
            }

            byte[] cuerpoRespuesta = ocspThread.getResponse();//metodo.getResponseBody();
            if (cuerpoRespuesta == null) {
            	String mensajeError = OCSPConstants.LIBRERIA_OCSP_ERROR_10 + OCSPConstants.DOS_PUNTOS_ESPACIO + servidorURL;
            	log.error( OCSPConstants.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + "Respuesta vacía");
            	throw new OCSPClientException(mensajeError);
            }
            log.info(OCSPConstants.MENSAJE_RESPUESTA_OBTENIDA);

            try {
            	OCSPResponse = new OCSPResp(cuerpoRespuesta);
            } catch (IOException e) {
            	log.error( OCSPConstants.MENSAJE_ERROR_SECUENCIA_BYTES_RESPUESTA + e.getMessage());
                throw new OCSPClientException(OCSPConstants.LIBRERIA_OCSP_ERROR_5 + OCSPConstants.DOS_PUNTOS_ESPACIO + e.getMessage());
            }

            /*
              Estados de la respuesta OCSP
                successful            (0) La respuesta tiene una confirmación válida
                malformedRequest      (1) La petición no se realizó de forma correcta
                internalError         (2) Error interno
                tryLater              (3) Vuelva a intentarlo
                    -				  (4) no se utiliza
                sigRequired           (5) La petición debe estar firmada
                unauthorized          (6) No se ha podido autorizar la petición

            */
            
            processResponse(OCSPResponse, respuesta, certificadoId);
        } catch (HttpException e) {
        	log.error( OCSPConstants.MENSAJE_VIOLACION_HTTP + e.getMessage());
        	throw new OCSPClientException(OCSPConstants.LIBRERIA_OCSP_ERROR_7 + OCSPConstants.DOS_PUNTOS_ESPACIO + e.getMessage());
        } catch (IOException e)  {
        	String mensajeError = OCSPConstants.LIBRERIA_OCSP_ERROR_10 + OCSPConstants.DOS_PUNTOS_ESPACIO + servidorURL;
        	log.error( OCSPConstants.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage());
        	throw new OCSPClientException(mensajeError);
        } finally {
            method.releaseConnection();
        }
        
        return respuesta ;
    }

    //FIXME return OCSPResponse
    public static void processResponse(OCSPResp inResp, OCSPResponse outResp, CertificateID certID) throws OCSPClientException, IOException {
    	outResp.setRespuesta(inResp);
        if (inResp.getStatus() != 0)
        {
        	log.info(OCSPConstants.MENSAJE_OCSP_NOT_SUCCESSFUL);
        	switch (inResp.getStatus())
        	{
	            case 1:
	            			log.warn(OCSPConstants.MENSAJE_OCSP_MALFORMED_REQUEST);
	            			outResp.setNroRespuesta(OCSPConstants.MALFORMEDREQUEST);
	            			outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_OCSP_RESPUESTA_1);
	            			
	            			break;
	            case 2:
	            			log.warn(OCSPConstants.MENSAJE_OCSP_INTERNAL_ERROR);
	            			outResp.setNroRespuesta(OCSPConstants.INTERNALERROR);
	            			outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_OCSP_RESPUESTA_2);
	            			break;
	            case 3:
	            			log.warn(OCSPConstants.MENSAJE_OCSP_TRY_LATER);
	            			outResp.setNroRespuesta(OCSPConstants.TRYLATER);
	            			outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_OCSP_RESPUESTA_3);
	            			break;
	            case 5:
	            			log.warn(OCSPConstants.MENSAJE_OCSP_SIG_REQUIRED);
	            			outResp.setNroRespuesta(OCSPConstants.SIGREQUIRED);
	            			outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_OCSP_RESPUESTA_4);
	            			break;
	            case 6:
	            			log.warn(OCSPConstants.MENSAJE_OCSP_UNAUTHORIZED);
	            			outResp.setNroRespuesta(OCSPConstants.UNAUTHORIZED);
	            			outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_OCSP_RESPUESTA_5);
	            			break;
        	}
        }
        else
        {
            try
            {
            	log.info(OCSPConstants.MENSAJE_OCSP_SUCCESSFUL);
                BasicOCSPResp respuestaBasica = (BasicOCSPResp)inResp.getResponseObject();
				
                try {
                	X509Certificate certs[] = respuestaBasica.getCerts(OCSPConstants.SUN);
                	if ((certs != null) && (certs.length > 0)) {
                		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>(certs.length);
                		for (int i = 0; i < certs.length; i++)
                			list.add(certs[i]);
                		outResp.setOCSPSigner(list);
                	}
				} catch (NoSuchProviderException e) {
					log.info(e.getMessage(), e);
				} catch (OCSPException e) {
					log.info(e.getMessage(), e);
				}
                
                SingleResp[] arrayRespuestaBasica = respuestaBasica.getResponses();
                outResp.setTiempoRespuesta(respuestaBasica.getProducedAt());
                ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
                outResp.setResponder(respID);
                StringBuffer mensaje = new StringBuffer(OCSPConstants.MENSAJE_RECIBIDO_ESTADO_NO_DEFINIDO);

                boolean found = false;
                for (int i = 0; i<arrayRespuestaBasica.length;i++)
                {
                	// Comprueba si es la respuesta esperada
                	SingleResp sr = arrayRespuestaBasica[i];
                	if (!certID.equals(sr.getCertID()))
            			continue;
                	
                	found = true;
                	Object certStatus = arrayRespuestaBasica[i].getCertStatus();
                	if (certStatus == null)
                    {
                    	log.info(OCSPConstants.ESTADO_CERTIFICADO_GOOD);
                    	outResp.setNroRespuesta(OCSPConstants.GOOD);
                    	outResp.setMensajeRespuesta(new String(Base64Coder.encode(inResp.getEncoded())));
                    }
                	else if (certStatus instanceof RevokedStatus)
                    {
                    	log.info(OCSPConstants.ESTADO_CERTIFICADO_REVOKED);
                    	outResp.setFechaRevocacion(((RevokedStatus)certStatus).getRevocationTime());
                    	outResp.setNroRespuesta(OCSPConstants.REVOKED);

                        /*
                        Razones de revocación
                        	unused 					(0) Sin uso
                        	keyCompromise 			(1) Se sospecha que la clave del certificado ha quedado comprometida
                        	cACompromise			(2) Se sospecha que la clave que firmó el certificado ha quedado comprometida
                        	affiliationChanged		(3) Se han cambiado los datos particulares del certificado
                        	superseded	      		(4) El certificado ha sido reemplazado por otro
                        	cessationOfOperation	(5) El certificado ha dejado de operar
                        	certificateHold 		(6) El certificado momentáneamente ha dejado de operar
						*/

                        RevokedStatus revoked = (RevokedStatus)certStatus;
                        if (revoked.hasRevocationReason())
                        {
	                        switch (revoked.getRevocationReason())
	                        {
	                        
	                        	case 1:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_1);
                        			break;
	                        	case 2:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_2);
                    				break;
	                        	case 3:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_3);
                    				break;
	                        	case 4:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_4);
                    				break;
	                        	case 5:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_5);
                    				break;
	                        	case 6:
	                        		outResp.setMensajeRespuesta(OCSPConstants.LIBRERIA_RAZON_REVOCACION_6);
                    				break;
	                        	default:
	                        		outResp.setMensajeRespuesta(OCSPConstants.CADENA_VACIA);
	                        }
                        }
                        else
                        	outResp.setMensajeRespuesta(OCSPConstants.CADENA_VACIA);
                    }
                    else if (certStatus instanceof UnknownStatus)
                    {
                    	
                    	log.info(OCSPConstants.ESTADO_CERTIFICADO_UNKNOWN);
                    	outResp.setNroRespuesta(OCSPConstants.UNKNOWN) ;
                    	outResp.setMensajeRespuesta(OCSPConstants.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                    }
                    else
                    {
                    	mensaje.append(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    	log.info( mensaje.toString());
                    	outResp.setNroRespuesta(OCSPConstants.ERROR) ;
                    	outResp.setMensajeRespuesta(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    }
                }
                
                if (!found) {
                	log.info(OCSPConstants.ESTADO_CERTIFICADO_UNKNOWN);
                	outResp.setNroRespuesta(OCSPConstants.UNKNOWN) ;
                	outResp.setMensajeRespuesta(OCSPConstants.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                }
            }
            catch (OCSPException e)
            {
            	log.error("Basic OCSP response instantiation error: " + e.getMessage());
            	throw new OCSPClientException("Basic OCSP response instantiation error: " + e.getMessage());
            }
        }
    }
    
	/**
	 * <p>Establece un gestionador de las conexiones SSL para el cliente.</p>
	 * @param sslmanager Gestionador de las conexiones SSL
     *
     **/

	public static void setSSLManager(ISSLManager sslmanager, Integer port) {
		Protocol authhttps = new Protocol("https", (ProtocolSocketFactory) new OwnSSLProtocolSocketFactory(sslmanager), port);
		Protocol.registerProtocol("https", authhttps);
	}
	
	/**
     * <p>Establece el tiempo máximo de espera para solicitar una respuesta OCSP.</p>
     * @param timeMilis Tiempo máximo de espera en milisegundos
     */
    public void setTimeOut(Integer timeMilis) {
    	if (timeMilis != null && timeMilis > 0) {
    		log.debug("Se establece el tiempo máximo de espera a " + timeMilis);
    		timeOut = timeMilis;
    	} else {
    		log.error("No se pudo establecer el valor de TimeOut a " + timeMilis + ". Se toma el valor por defecto.");
    		timeOut = INT_20000;
    	}
    }
    
    public synchronized void abort() {
    	if (method != null)
    		method.abort();
    }
    
    class MethodThread extends Thread {
    	private int result = 0;
    	private byte[] response = null;

    	public MethodThread() {	}

    	public void run() {
    		try {
    			result = client.executeMethod(method);
    			response = method.getResponseBody();
    		} catch(Exception e) {
    			log.error(e);
    		} finally {
    			method.releaseConnection();
    		}
    	}

		public int getResult() {
			return result;
		}
		public byte[] getResponse() {
			return response;
		}
		public void setResponse(byte[] res) {
			response = res;
		}
    }
    
    private void retryPost(int estadoCodigo, OCSPReq peticionOCSP, MethodThread ocspThread, int dataLenght) throws OCSPClientException, OCSPProxyException {
    	if (method == null || method.isAborted()) {
    		log.debug("Aborted by user");
    		return;
    	}
    	log.info("OCSP Status: retrying with HttpPOST");
		HttpURLConnection conn = null;
		InputStream in = null;
		try {
			conn = (HttpURLConnection) new URL(servidorURL).openConnection();
			conn.setConnectTimeout(7000);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "application/ocsp-request");
			conn.setRequestProperty("Accept", "application/ocsp-response");
			conn.setRequestProperty("Content-Length", String.valueOf(dataLenght));
			conn.setUseCaches (false);
			conn.setDoOutput(true);        			

			DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
			wr.write(peticionOCSP.getEncoded());
			wr.flush ();
			wr.close ();	

			if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {

				in = (InputStream) conn.getContent();
				OCSPResp ocspResponse = new OCSPResp(in); 
				int status = ocspResponse.getStatus();
				
				if (ocspResponse != null && ocspResponse.getEncoded().length > 0) {
					if (log.isDebugEnabled()) {
						log.debug("Successful connection with HttpURLConnection");
					}
					estadoCodigo = HttpURLConnection.HTTP_OK;
					ocspThread.setResponse(ocspResponse.getEncoded());
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Unexpected response received: " + status);
					}
					throw new OCSPClientException("Method execution failed: " + method.getStatusLine());
				}
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Error response received:" + conn.getResponseCode() + " - " + conn.getResponseMessage());
				}
			}
		} catch (Exception e1) {
			if (log.isDebugEnabled()) {
				log.debug("Failed connection with HttpURLConnection", e1);
			}
			throw new OCSPClientException(e1);
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
			if (in != null) {
				try { in.close(); } catch (IOException e1) {
					if (log.isDebugEnabled()) {
						log.debug("Write channel could not be closed", e1);
					}
				}
			}
		}          	

        if (estadoCodigo == HttpStatus.SC_USE_PROXY)
        	throw new OCSPProxyException("A proxy must be set up in order to perform the query");
        else if (estadoCodigo != HttpURLConnection.HTTP_OK) {
        	log.error("Method execution failed: " + method.getStatusLine());
        	throw new OCSPClientException("Method execution failed: " + method.getStatusLine());
        }
    }
}
