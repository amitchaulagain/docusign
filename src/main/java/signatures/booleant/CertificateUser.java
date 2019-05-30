/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.booleant;

public class CertificateUser {
    String name;
    String email;
    String city;
    String state;
    String organisation;
    String organistationUnit;
    String street;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getOrganisation() {
        return organisation;
    }

    public void setOrganisation(String organisation) {
        this.organisation = organisation;
    }

    public String getOrganistationUnit() {
        return organistationUnit;
    }

    public void setOrganistationUnit(String organistationUnit) {
        this.organistationUnit = organistationUnit;
    }

    public String getStreet() {
        return street;
    }

    public void setStreet(String street) {
        this.street = street;
    }

    @Override
    public String toString() {
        return "CN=" + this.name + "," +
                "OU=" + this.organistationUnit + "," +
                "O=" + this.organisation + "," +
                "L=" + this.city + "," +
                "ST=" + this.street;
    }
}
