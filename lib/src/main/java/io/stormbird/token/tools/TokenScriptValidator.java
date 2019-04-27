package io.stormbird.token.tools;

import io.stormbird.token.entity.SignatureCheck;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import sun.security.x509.X509CertImpl;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Created by James on 27/04/2019.
 * Stormbird in Sydney
 */

/**
 * This is a simple example of validating an XML
 * Signature using the JSR 105 API. It assumes the key needed to
 * validate the signature is contained in a KeyValue KeyInfo.
 */
public class TokenScriptValidator {

    //
    // Synopsis: java Validate [document]
    //
    //    where "document" is the name of a file containing the XML document
    //    to be validated.
    //
    public static SignatureCheck check(InputStream fileStream) throws Exception
    {
        SignatureCheck result = new SignatureCheck();

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document xml = dBuilder.parse(fileStream);
        xml.getDocumentElement().normalize();

        // Find Signature element
        NodeList nl =
                xml.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0)
        {
            //throw new Exception("Cannot find Signature element");
            return result;
        }

        // Create a DOM XMLSignatureFactory that will be used to unmarshal the
        // document containing the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a DOMValidateContext and specify a KeyValue KeySelector
        // and document context
        DOMValidateContext valContext = new DOMValidateContext
                (new CertKeySelector(), nl.item(0));

        // unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature (generated above)
        result.isValid = signature.validate(valContext);

        if (result.isValid)
        {
            KeyInfo kInfo = signature.getKeyInfo();
            X509CertImpl cert = selectKeyData(kInfo.getContent());
            result.issuerPrincipal = cert.getIssuerX500Principal().getName();
            result.subjectPrincipal = cert.getSubjectX500Principal().getName();
            result.keyType = cert.getSigAlgName();

            for (Object o : kInfo.getContent())
            {
                XMLStructure xmlStructure = (XMLStructure) o;
                if (xmlStructure instanceof KeyName)
                {
                    result.keyName = ((KeyName) xmlStructure).getName();
                }
            }
        }
        else
        {
            System.err.println("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            // check the validation status of each Reference
            Iterator i = signature.getSignedInfo().getReferences().iterator();
            for (int j = 0; i.hasNext(); j++)
            {
                boolean refValid =
                        ((Reference) i.next()).validate(valContext);
                System.out.println("ref[" + j + "] validity status: " + refValid);
            }
        }

        return result;
    }

    protected static X509CertImpl selectKeyData(List list)
    {
        PublicKey recovered = null;
        X509CertImpl cert = null;

        for (int i = 0; i < list.size(); i++) {
            XMLStructure xmlStructure = (XMLStructure) list.get(i);

            if (xmlStructure instanceof KeyValue)
            {
                KeyValue kv = (KeyValue)xmlStructure;
                try
                {
                    recovered = kv.getPublicKey();
                }
                catch (KeyException e)
                {
                    e.printStackTrace();
                }
            }
            if (xmlStructure instanceof X509Data) {
                List<X509CertImpl> certList = ((X509Data)xmlStructure).getContent();
                cert = certList.get(certList.size() - 1);
                for (X509CertImpl crt : certList)
                {
                    try
                    {
                        crt.checkValidity();
                        if (recovered != null)
                        {
                            PublicKey certKey = crt.getPublicKey();
                            if (Arrays.equals(recovered.getEncoded(), certKey.getEncoded()))
                            {
                                cert = crt;
                            }
                        }
                        else
                        {
                            if (crt.getSigAlgName().equals("SHA256withECDSA"))
                            {
                                cert = crt;
                            }
                        }
                    }
                    catch (CertificateExpiredException e)
                    {
                        e.printStackTrace();
                    }
                    catch (CertificateNotYetValidException e)
                    {
                        e.printStackTrace();
                    }
                }
            }
        }

        return cert;
    }

    private static class CertKeySelector extends KeySelector
    {
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (Object o : list)
            {
                XMLStructure xmlStructure = (XMLStructure) o;
                if (xmlStructure instanceof KeyValue)
                {
                    KeyValue kv = (KeyValue) xmlStructure;
                    try
                    {
                        return new SimpleKeySelectorResult(kv.getPublicKey());
                    }
                    catch (KeyException e)
                    {
                        e.printStackTrace();
                    }
                }
            }
            X509CertImpl cert = selectKeyData(list);
            if (cert != null) return new SimpleKeySelectorResult(cert.getPublicKey());
            throw new KeySelectorException("No KeyValue element found!");
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() { return pk; }
    }
}
