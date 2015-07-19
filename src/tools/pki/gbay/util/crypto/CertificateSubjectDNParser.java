/*
 * 
 */
package tools.pki.gbay.util.crypto;

import java.util.StringTokenizer;

import tools.pki.gbay.configuration.SecurityConcepts;

public class CertificateSubjectDNParser
{
	String email = "";
	String ownerName = "";
	String id = "";
	String delegatedName = "";
	String principleName = "";
	String country = "";
	String organisation = "";
	String organisationUnit="";
	
	enum Atrributes{
		COUNTRY("C"),ORGANISATION("O"),UNIT("U"),ORGINISATION_UNIT("OU"),COMMONNAME("CN"),ID("ID"),EMAIL_SHORT("E"),EMAIL_LONG("EMAILADDRESS");
		private final String character;
		private Atrributes(String representor) {
			character = representor;
		}
		/**
		 * @return the character
		 */
		public String getCharacter() {
			return character;
		}
	}
	
	public CertificateSubjectDNParser(String dn)
	{
		extractDNFields(dn);
	}
	
	protected void extractDNFields(String dist)
	{
		if(dist != null && dist.trim().length() > 0)
		{
			StringTokenizer st = new StringTokenizer(dist,",");
			while(st.hasMoreTokens())
			{
				String field = st.nextToken();
				StringTokenizer st2 = new StringTokenizer(field,"=");
				if(st2.countTokens() > 1)
				{
					String fieldID = st2.nextToken();
					String fieldValue = st2.nextToken();
					processField(fieldID, fieldValue);
				}
			}
		}
	}

	protected void processField(String fieldID, String fieldValue)
	{
		if(fieldID != null && fieldID.length() > 0)
		{
			if(compareField(fieldID, Atrributes.EMAIL_SHORT) || compareField(fieldID, Atrributes.EMAIL_LONG))
			{
				setEmail(fieldValue);
			}
			else if(compareField(fieldID, Atrributes.COMMONNAME))
			{
				setOwnerName(fieldValue);
			}
			else if(compareField(fieldID, Atrributes.COUNTRY))
			{
				setCountry(fieldValue);
			}
			else if(compareField(fieldID, Atrributes.ORGANISATION))
			{
				setOrganisation(fieldValue);
			}
			else if(compareField(fieldID, Atrributes.ORGINISATION_UNIT))
			{
				int start = fieldValue.indexOf("-");
				if(start > 0)
				{
					setOrganisationUnit(fieldValue);
					String fid = fieldValue.substring(0,start);
					String fValue = fieldValue.substring(start+1);
					//For some custom made DN's so far we do not have this field in any of our certs

					if(compareField(fid, Atrributes.ID))
					{
						setId(fValue);
					}
					else if(fid.trim().equalsIgnoreCase("Bank Identifier"))
					{
						setDelegatedName(fValue);
					}
					else if(fid.trim().equalsIgnoreCase("Bank Name"))
					{
						setPrincipleName(fValue);
					}
					else{
						setDelegatedName(fValue);
					}
				}
				else{
					setDelegatedName(fieldValue);
				}
			}
		}
	}
	
	private boolean compareField(String fieldID , Atrributes att){
		return fieldID.trim().equalsIgnoreCase(att.getCharacter());
	}
	/**
	 * @return the delegatedName
	 */
	public String getDelegatedName()
	{
		return delegatedName;
	}

	/**
	 * @param delegatedName the delegatedName to set
	 */
	public void setDelegatedName(String delegatedName)
	{
		this.delegatedName = delegatedName;
	}

	/**
	 * @return the id
	 */
	public String getId()
	{
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id)
	{
		this.id = id;
	}

	/**
	 * @return the ownerName
	 */
	public String getOwnerName()
	{
		return ownerName;
	}

	/**
	 * @param ownerName the ownerName to set
	 */
	public void setOwnerName(String ownerName)
	{
		this.ownerName = ownerName;
	}

	/**
	 * @return the principleName
	 */
	public String getPrincipleName()
	{
		return principleName;
	}

	/**
	 * @param principleName the principleName to set
	 */
	public void setPrincipleName(String principleName)
	{
		this.principleName = principleName;
	}

	/**
	 * @return the email
	 */
	public String getEmail()
	{
		return email;
	}

	/**
	 * @param email the email to set
	 */
	public void setEmail(String email)
	{
		this.email = email;
	}

	/**
	 * @return the country
	 */
	public String getCountry() {
		return country;
	}

	/**
	 * @param country the country to set
	 */
	public void setCountry(String country) {
		this.country = country;
	}

	/**
	 * @return the organisation
	 */
	public String getOrganisation() {
		return organisation;
	}

	/**
	 * @param organisation the organisation to set
	 */
	public void setOrganisation(String organisation) {
		this.organisation = organisation;
	}

	/**
	 * @return the organisationUnit
	 */
	public String getOrganisationUnit() {
		return organisationUnit;
	}

	/**
	 * @param organisationUnit the organisationUnit to set
	 */
	public void setOrganisationUnit(String organisationUnit) {
		this.organisationUnit = organisationUnit;
	}
}


