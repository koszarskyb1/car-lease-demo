package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"encoding/json"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
    "io/ioutil"
	"regexp"
	
)

//==============================================================================================================================
//	 Participant types - Each participant type is mapped to an integer which we use to compare to the value stored in a
//						 user's eCert
//==============================================================================================================================
const   DU_RHONE   				=  1
const   PRINTER 				=  2
const   SUPPLIER  				=  3
const   SHIPPING_CO 			=  4
const   IBM      				=  5


//==============================================================================================================================
//	 Status types - Asset lifecycle is broken down into 7 statuses, this is part of the business logic to determine what can 
//					be done to the chocolates at points in it's lifecycle
//==============================================================================================================================
const   STATE_CONCEPTING  			=  0
const 	STATE_PRINTING				=  1
const	STATE_SUPPLYING				=  2
const	STATE_TESTING               =  3
const   STATE_PRODUCTION			=  4
const   STATE_DELIVERY			 	=  5
const	STATE_DELIVERED				=  6

//==============================================================================================================================
//	 Structure Definitions 
//==============================================================================================================================
//	Chaincode - A blank struct for use with Shim (A HyperLedger included go file used for get/put state
//				and other HyperLedger functions)
//==============================================================================================================================
type  SimpleChaincode struct {
}

//==============================================================================================================================
//	Chocolates - Defines the structure for a chocolate object. JSON on right tells it what JSON fields to map to
//			  that element when reading a JSON object into the struct e.g. JSON make -> Struct Make.
//==============================================================================================================================
type Chocolates struct {
	//Company Infor and ID
	Chocolatier    	string `json:"chocolatier"`
	EstablishDate	string `json:"establishDate"`
	ChocoID         string `json:"ID"`
	//Supply Info
	BoxOrderDate	string `json:"boxOrderDate"`
	BoxDelvDate		string `json:"boxDelvDate"`
	IngredOrderDate	string `json:"ingredOrderDate"`
	IngredDelvDate	string `json:"ingredOrderDate"`
	IngredOrigin	string `json:"ingredOrigin"` 
	// Recipe Info
	Contributers  []string `json:"contributers"`
	Ingredients	  []string `json:"ingredients"`
	Method			string `json:"method"`
	//Taste Testing Info
	Test	        string `json:"test"`
	Testers       []string `json:"testers"`
	Revisions	  []string `json:"revisions"`
	TestDate        string `json:"testDate"`
	DateFinalized	string `json:"dateFinalized"`
	//Production/Delivery Info
	DateProduced	string `json:"dateProduced"`
	DatePackaged 	string `json:"datePackaged"`
	DateArrived     string `json:"dateArrived"`
	DelivererID		string `json:"delivererID"`
	//Status info
	Owner			int    `json:"owner"`
	Delivered		bool   `json:"delivered"`
	Status			int	   `json:"status"`
}


//==============================================================================================================================
//	Choco Holder - Defines the structure that holds all the IDs for chocolates that have been created.
//				Used as an index when querying all chocolates.
//==============================================================================================================================

type Choco_Holder struct {
	ChocoIDs 	[]string `json:"chocoIDs"`
}

//==============================================================================================================================
//	ECertResponse - Struct for storing the JSON response of retrieving an ECert. JSON OK -> Struct OK
//==============================================================================================================================
type ECertResponse struct {
	OK string `json:"OK"`
	Error string `json:"Error"`
}					


//==============================================================================================================================
//	Init Function - Called when the user deploys the chaincode																	
//==============================================================================================================================
func (t *SimpleChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	
	//Args
	//				0
	//			peer_address
	
	
	var chocoIDs Choco_Holder
	
	bytes, err := json.Marshal(chocoIDs)
	
															if err != nil { return nil, errors.New("Error creating Choco_Holder record") }
																
	err = stub.PutState("chocoIDs", bytes)
	
	
	err = stub.PutState("Peer_Address", []byte(args[0]))
															if err != nil { return nil, errors.New("Error storing peer address") }										
	
	return nil, nil
}

//==============================================================================================================================
//	 General Functions
//==============================================================================================================================
//	 get_ecert - Takes the name passed and calls out to the REST API for HyperLedger to retrieve the ecert
//				 for that user. Returns the ecert as retrived including html encoding.
//==============================================================================================================================
func (t *SimpleChaincode) get_ecert(stub *shim.ChaincodeStub, name string) ([]byte, error) {
	
	var cert ECertResponse
	
	peer_address, err := stub.GetState("Peer_Address")
															if err != nil { return nil, errors.New("Error retrieving peer address") }

	response, err := http.Get("http://"+string(peer_address)+"/registrar/"+name+"/ecert") 	// Calls out to the HyperLedger REST API to get the ecert of the user with that name
    
															fmt.Println("HTTP RESPONSE", response)
															
															if err != nil { return nil, errors.New("Error calling ecert API") }
	
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)					// Read the response from the http callout into the variable contents
															
															fmt.Println("HTTP BODY:", string(contents))
															
															if err != nil { return nil, errors.New("Could not read body") }
	
	err = json.Unmarshal(contents, &cert)
	
															if err != nil { return nil, errors.New("Could not retrieve ecert for user: "+name) }
															
															fmt.Println("CERT OBJECT:", cert)
															
															if cert.Error != "" { fmt.Println("GET ECERT ERRORED: ", cert.Error); return nil, errors.New(cert.Error)}
	
	return []byte(string(cert.OK)), nil
}

//==============================================================================================================================
//	 get_caller - Retrieves the username of the user who invoked the chaincode.
//				  Returns the username as a string.
//==============================================================================================================================

func (t *SimpleChaincode) get_username(stub *shim.ChaincodeStub) (string, error) {

	bytes, err := stub.GetCallerCertificate();
															if err != nil { return "", errors.New("Couldn't retrieve caller certificate") }
	x509Cert, err := x509.ParseCertificate(bytes);				// Extract Certificate from result of GetCallerCertificate						
															if err != nil { return "", errors.New("Couldn't parse certificate")	}
															
	return x509Cert.Subject.CommonName, nil
}

//==============================================================================================================================
//	 check_affiliation - Takes an ecert as a string, decodes it to remove html encoding then parses it and checks the
// 				  		certificates common name. The affiliation is stored as part of the common name.
//==============================================================================================================================

func (t *SimpleChaincode) check_affiliation(stub *shim.ChaincodeStub, cert string) (int, error) {																																																					
	
	decodedCert, err := url.QueryUnescape(cert);    				// make % etc normal //
	
															if err != nil { return -1, errors.New("Could not decode certificate") }
	
	pem, _ := pem.Decode([]byte(decodedCert))           				// Make Plain text   //

	x509Cert, err := x509.ParseCertificate(pem.Bytes);				// Extract Certificate from argument //
														
															if err != nil { return -1, errors.New("Couldn't parse certificate")	}

	cn := x509Cert.Subject.CommonName
	
	res := strings.Split(cn,"\\")
	
	affiliation, _ := strconv.Atoi(res[2])
	
	return affiliation, nil
}

//==============================================================================================================================
//	 get_caller_data - Calls the get_ecert and check_role functions and returns the ecert and role for the
//					 name passed.
//==============================================================================================================================

func (t *SimpleChaincode) get_caller_data(stub *shim.ChaincodeStub) (string, int, error){

	user, err := t.get_username(stub)
																		if err != nil { return "", -1, err }
																		
	ecert, err := t.get_ecert(stub, user);					
																		if err != nil { return "", -1, err }

	affiliation, err := t.check_affiliation(stub,string(ecert));			
																		if err != nil { return "", -1, err }

	return user, affiliation, nil
}

//==============================================================================================================================
//	 retrieve_chocoID - Gets the state of the data at chocoID in the ledger then converts it from the stored 
//					JSON into the Chocolates struct for use in the contract. Returns the chocolates struct.
//					Returns empty c if it errors.
//==============================================================================================================================
func (t *SimpleChaincode) retrieve_chocoID(stub *shim.ChaincodeStub, chocoID string) (Chocolates, error) {
	
	var c Chocolates

	bytes, err := stub.GetState(chocoID)	;					
				
															if err != nil {	fmt.Printf("RETRIEVE_CHOCOID: Failed to invoke chocolate_code: %s", err); return c, errors.New("RETRIEVE_CHOCOID: Error retrieving chocolates with chocoID = " + chocoID) }

	err = json.Unmarshal(bytes, &c)	;						

															if err != nil {	fmt.Printf("RETRIEVE_CHOCOID: Corrupt chocolates record "+string(bytes)+": %s", err); return c, errors.New("RETRIEVE_CHOCOID: Corrupt chocolates record"+string(bytes))	}
	
	return c, nil
}

///////      8.3.2016   4:30 p.m.

//==============================================================================================================================
// save_changes - Writes to the ledger the Chocolates struct passed in a JSON format. Uses the shim file's 
//				  method 'PutState'.
//==============================================================================================================================
func (t *SimpleChaincode) save_changes(stub *shim.ChaincodeStub, c Chocolates) (bool, error) {
	 
	bytes, err := json.Marshal(c)
	
																if err != nil { fmt.Printf("SAVE_CHANGES: Error converting chocolates record: %s", err); return false, errors.New("Error converting chocolates record") }

	err = stub.PutState(c.chocoID, bytes)
	
																if err != nil { fmt.Printf("SAVE_CHANGES: Error storing chocolates record: %s", err); return false, errors.New("Error storing chocolates record") }
	
	return true, nil
}

//==============================================================================================================================
//	 Router Functions
//==============================================================================================================================
//	Invoke - Called on chaincode invoke. Takes a function name passed and calls that function. Converts some
//		  initial arguments passed to other things for use in the called function e.g. name -> ecert
//==============================================================================================================================
func (t *SimpleChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	
	caller, caller_affiliation, err := t.get_caller_data(stub)

	if err != nil { return nil, errors.New("Error retrieving caller information")}

	
	if function == "create_chocolates" { return t.create_chocolates(stub, caller, caller_affiliation, args[0])
	} else { 																				// If the function is not a create then there must be chocolates so we need to retrieve the chocolates.
		
		argPos := 1
		
		if function == "finish_delivery" {																// If its a delivery then only two arguments are passed (no update value) all others have three arguments and the chocoID is expected in the last argument
			argPos = 0
		}
		
		v, err := t.retrieve_chocoID(stub, args[argPos])
		
																							if err != nil { fmt.Printf("INVOKE: Error retrieving chocoID: %s", err); return nil, errors.New("Error retrieving chocoID") }
																		
		if strings.Contains(function, "update") == false           && 
		   function 							!= "finish_delivery"    { 									// If the function is not an update or a delivery it must be a transfer so we need to get the ecert of the recipient.
			
				ecert, err := t.get_ecert(stub, args[0]);					
				
																		if err != nil { return nil, err }

				rec_affiliation, err := t.check_affiliation(stub,string(ecert));	
				
																		if err != nil { return nil, err }
				
				if 		   function == "concepting_to_printing"    { return t.concepting_to_printing(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				} else if  function == "printing_to_supplying"      { return t.printing_to_supplying(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				} else if  function == "supplying_to_testing"       { return t.supplying_to_testing(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				} else if  function == "testing_to_produciton"     { return t.testing_to_produciton(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				} else if  function == "production_to_delivery"    { return t.production_to_delivery(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				} else if  function == "delivery_to_delivered"     { return t.delivery_to_delivered(stub, c, caller, caller_affiliation, args[0], rec_affiliation)
				}


		} else if function == "update_boxOrderDate"  	    	{ return t.update_boxOrderDate(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_boxDelvDate"       		{ return t.update_boxDelvDate(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_ingredOrderDate" 			{ return t.update_ingredOrderDate(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_ingredDelvDate" 			{ return t.update_ingredDelvDate(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_ingredOrigin" 			{ return t.update_ingredOrigin(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_contributers" 			{ return t.update_contributers(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_ingredients" 				{ return t.update_ingredients(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_test" 					{ return t.update_test(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_testers"  	 			{ return t.update_testers(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_revisions" 				{ return t.update_revisions(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_dateFinalized" 			{ return t.update_dateFinalized(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_delivererID" 				{ return t.update_delivererID(stub, c, caller, caller_affiliation, args[0])
		} else if function == "update_receipt" 					{ return t.update_receipt(stub, c, caller, caller_affiliation, args[0])
		} else if function == "finish_delivery" 			    { return t.finish_delivery(stub, c, caller, caller_affiliation) }
		}
		
																						return nil, errors.New("Function of that name doesn't exist.")
			
	}
}
//=================================================================================================================================	
//	Query - Called on chaincode query. Takes a function name passed and calls that function. Passes the
//  		initial arguments passed are passed on to the called function.
//=================================================================================================================================	
func (t *SimpleChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	
															
	caller, caller_affiliation, err := t.get_caller_data(stub)

																							if err != nil { fmt.Printf("QUERY: Error retrieving caller details", err); return nil, errors.New("QUERY: Error retrieving caller details") }
															
	if function == "get_chocolate_details" { 
	
			if len(args) != 1 { fmt.Printf("Incorrect number of arguments passed"); return nil, errors.New("QUERY: Incorrect number of arguments passed") }
	
	
			v, err := t.retrieve_chocoID(stub, args[0])
																							if err != nil { fmt.Printf("QUERY: Error retrieving chocoID: %s", err); return nil, errors.New("QUERY: Error retrieving chocoID "+err.Error()) }
	
			return t.get_chocolate_details(stub, c, caller, caller_affiliation)
			
	} else if function == "get_chocos" {
			return t.get_chocos(stub, caller, caller_affiliation)
	}
																							return nil, errors.New("Received unknown function invocation")
}

//=================================================================================================================================
//	 Create Function
//=================================================================================================================================									
//	 Create Chocolates - Creates the initial JSON for the chocolates and then saves it to the ledger.									
//=================================================================================================================================
func (t *SimpleChaincode) create_chocolates(stub *shim.ChaincodeStub, caller string, caller_affiliation int, chocoID string) ([]byte, error) {								


	var c Chocolates																																										
	
			// Variables to define the JSON
		//Company Info and ID
	chocolatier    	:= "\"Chocolatier\":\"Du Rhone-IBM\", "
	establishDate	:= "\"Chocolatier\":\"UNDEFINED\", "
	chocoID         := "\"Chocolatier\":\""+chocoID+"\", "
	//Supply Info
	boxOrderDate	:= "\"Chocolatier\":\"UNDEFINED\", "
	boxDelvDate		:= "\"Chocolatier\":\"UNDEFINED\", "
	ingredOrderDate	:= "\"Chocolatier\":\"UNDEFINED\", "
	ingredDelvDate	:= "\"Chocolatier\":\"UNDEFINED\", "
	ingredOrigin	:= "\"Chocolatier\":\"UNDEFINED\", "
	// Recipe Info
	contributers    := "\"Chocolatier\":{} "
	ingredients	    := "\"Chocolatier\":{} "
	method			:= "\"Chocolatier\":\"Chef Watson + Chocolatier\", "
	//Taste Testing Info
	test	        := "\"Chocolatier\":\"UNDEFINED\", "
	testers         := "\"Chocolatier\":{} "
	revisions	    := "\"Chocolatier\":{} "
	testDate        := "\"Chocolatier\":\"UNDEFINED\", "
	dateFinalized	:= "\"Chocolatier\":\"UNDEFINED\", "
	//Production/Delivery Info
	dateProduced	:= "\"Chocolatier\":\"UNDEFINED\", "
	datePackaged 	:= "\"Chocolatier\":\"UNDEFINED\", "
	dateArrived     := "\"Chocolatier\":\"UNDEFINED\", "
	delivererID		:= "\"Chocolatier\":\"UNDEFINED\", "
	//Status info
	owner			:= "\"Chocolatier\":2, "
	delivered		:= "\"Chocolatier\":false"
	status			:= "\"Chocolatier\":0, "

	
	chocolates_json := "{"+chocolatier+establishDate+chocoID+boxOrderDate+boxDelvDate+ingredOrderDate+ingredDelvDate+ingredOrigin
	+contributers+ingredients+method+test+testers+revisions+testDate+dateFinalized+dateProduced+datePackaged+dateArrived+delivererID+delivered+status+"}" 	// Concatenates the variables to create the total JSON object
	
	matched, err := regexp.Match("^[A-z][A-z][0-9]{7}", []byte(chocoID))  				// matched = true if the chocoID passed fits format of two letters followed by seven digits
	
																		if err != nil { fmt.Printf("CREATE_CHOCOLATES: Invalid chocoID: %s", err); return nil, errors.New("Invalid chocoID") }
	
	if 				chocoID  == "" 	 || 
					matched == false    {
																		fmt.Printf("CREATE_CHOCOLATES: Invalid chocoID provided");
																		return nil, errors.New("Invalid chocoID provided")
	}

	err = json.Unmarshal([]byte(chocolates_json), &c)							// Convert the JSON defined above into a chocolates object for go
	
																		if err != nil { return nil, errors.New("Invalid JSON object") }

	record, err := stub.GetState(c.chocoID) 								// If not an error then a record exists so cant create a new chocolates with this chocoID as it must be unique
	
																		if record != nil { return nil, errors.New("Chocolates already exists") }
	
	if 	caller_affiliation != DU_RHONE {							// Only DU_RHONE can create a new chocoID

																		return nil, errors.New("Permission Denied")
	}
	
	_, err  = t.save_changes(stub, c)									
			
																		if err != nil { fmt.Printf("CREATE_CHOCOLATES: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	bytes, err := stub.GetState("chocoIDs")

																		if err != nil { return nil, errors.New("Unable to get chocoIDs") }
																		
	var chocoIDs Choco_Holder
	
	err = json.Unmarshal(bytes, &chocoIDs)
	
																		if err != nil {	return nil, errors.New("Corrupt Choco_Holder record") }
															
	chocoIDs.Chocos = append(chocoIDs.Chocos, chocoID)
	
	
	bytes, err = json.Marshal(chocoIDs)
	
															if err != nil { fmt.Print("Error creating Choco_Holder record") }

	err = stub.PutState("chocoIDs", bytes)

															if err != nil { return nil, errors.New("Unable to put the state") }
	
	return nil, nil

}

//=================================================================================================================================
//	 Transfer Functions
//=================================================================================================================================
//	 concepting_to_printing
//=================================================================================================================================
func (t *SimpleChaincode) concepting_to_printing(stub *shim.ChaincodeStub, c Chocolates, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if     	c.Status				== STATE_CONCEPTING	&&
			c.Owner					== caller			&&
			caller_affiliation		== DU_RHONE			&&
			recipient_affiliation	== PRINTER			&&
			c.Delivered				== false			{		// If the roles and users are ok 
	
					c.Owner  = recipient_name			// then make the owner the new owner
					c.Status = STATE_PRINTING			//Update State
					
	} else {									// Otherwise if there is an error
	
															fmt.Printf("CONCEPTING_TO_PRINTING: Permission Denied");
															return nil, errors.New("Permission Denied")
	
	}
	
	_, err := t.save_changes(stub, c)						// Write new state

															if err != nil {	fmt.Printf("CONCEPTING_TO_PRINTING: Error saving changes: %s", err); return nil, errors.New("Error saving changes")	}
														
	return nil, nil									// We are Done
	
}

//=================================================================================================================================
//	 printing_to_supplying
//=================================================================================================================================
func (t *SimpleChaincode) printing_to_supplying(stub *shim.ChaincodeStub, c Chocolates, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if 		c.EstablishDate == "UNDEFINED" || 					
			c.Ingredients   == {} 		   ||
			c.Contributers  == {}		   ||
			c.Method        == "UNDEFINED" || 
			c.DateFinalized == "UNDEFINED"	{
														//If any part of the chocolates is undefined it has not bene fully concepted so cannot be sent
															fmt.Printf("PRINTING_TO_SUPPLYING: Chocolates not fully defined")
															return nil, errors.New("Chocolates not fully defined")
	}
	
	if 		c.Status				== STATE_PRINTING		&& 
			c.Owner					== caller				&& 
			caller_affiliation		== PRINTER				&&
			recipient_affiliation	== SUPPLIER				&& 
			C.Delivered             == false							{
			
					v.Owner = recipient_name
					v.Status = STATE_SUPPLYING
					
	} else {
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, c)
	
															if err != nil { fmt.Printf("PRINTING_TO_SUPPLYING: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//////////// 8.4.2016      4:47 p.m.

//=================================================================================================================================
//	 private_to_private
//=================================================================================================================================
func (t *SimpleChaincode) private_to_private(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if 		v.Status				== STATE_PRIVATE_OWNERSHIP	&&
			v.Owner					== caller					&&
			caller_affiliation		== PRIVATE_ENTITY			&& 
			recipient_affiliation	== PRIVATE_ENTITY			&&
			v.Scrapped				== false					{
			
					v.Owner = recipient_name
					
	} else {
		
															return nil, errors.New("Permission denied")
	
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("PRIVATE_TO_PRIVATE: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 private_to_lease_company
//=================================================================================================================================
func (t *SimpleChaincode) private_to_lease_company(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if 		v.Status				== STATE_PRIVATE_OWNERSHIP	&& 
			v.Owner					== caller					&& 
			caller_affiliation		== PRIVATE_ENTITY			&& 
			recipient_affiliation	== LEASE_COMPANY			&& 
			v.Scrapped     			== false					{
		
					v.Owner = recipient_name
					
	} else {
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
															if err != nil { fmt.Printf("PRIVATE_TO_LEASE_COMPANY: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 lease_company_to_private
//=================================================================================================================================
func (t *SimpleChaincode) lease_company_to_private(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if		v.Status				== STATE_PRIVATE_OWNERSHIP	&&
			v.Owner  				== caller					&& 
			caller_affiliation		== LEASE_COMPANY			&& 
			recipient_affiliation	== PRIVATE_ENTITY			&& 
			v.Scrapped				== false					{
		
				v.Owner = recipient_name
	
	} else {
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
															if err != nil { fmt.Printf("LEASE_COMPANY_TO_PRIVATE: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 private_to_scrap_merchant
//=================================================================================================================================
func (t *SimpleChaincode) private_to_scrap_merchant(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {
	
	if		v.Status				== STATE_PRIVATE_OWNERSHIP	&&
			v.Owner					== caller					&& 
			caller_affiliation		== PRIVATE_ENTITY			&& 
			recipient_affiliation	== SCRAP_MERCHANT			&&
			v.Scrapped				== false					{
			
					v.Owner = recipient_name
					v.Status = STATE_BEING_SCRAPPED
	
	} else {
		
															return nil, errors.New("Permission denied")
	
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("PRIVATE_TO_SCRAP_MERCHANT: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 Update Functions
//=================================================================================================================================
//	 update_vin
//=================================================================================================================================
func (t *SimpleChaincode) update_vin(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, new_value string) ([]byte, error) {
	
	new_vin, err := strconv.Atoi(string(new_value)) 		                // will return an error if the new vin contains non numerical chars
	
															if err != nil || len(string(new_value)) != 15 { return nil, errors.New("Invalid value passed for new VIN") }
	
	if 		v.Status			== STATE_MANUFACTURE	&& 
			v.Owner				== caller				&&
			caller_affiliation	== MANUFACTURER			&&
			v.VIN				== 0					&&			// Can't change the VIN after its initial assignment
			v.Scrapped			== false				{
			
					v.VIN = new_vin					// Update to the new value
	} else {
	
															return nil, errors.New("Permission denied")
		
	}
	
	_, err  = t.save_changes(stub, v)						// Save the changes in the blockchain
	
															if err != nil { fmt.Printf("UPDATE_VIN: Error saving changes: %s", err); return nil, errors.New("Error saving changes") } 
	
	return nil, nil
	
}


//=================================================================================================================================
//	 update_registration
//=================================================================================================================================
func (t *SimpleChaincode) update_registration(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, new_value string) ([]byte, error) {

	
	if		v.Owner				== caller			&& 
			caller_affiliation	!= SCRAP_MERCHANT	&&
			v.Scrapped			== false			{
			
					v.Reg = new_value
	
	} else {
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("UPDATE_REGISTRATION: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 update_colour
//=================================================================================================================================
func (t *SimpleChaincode) update_colour(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, new_value string) ([]byte, error) {
	
	if 		v.Owner				== caller				&&
			caller_affiliation	== MANUFACTURER			&&/*((v.Owner				== caller			&&
			caller_affiliation	== MANUFACTURER)		||
			caller_affiliation	== AUTHORITY)			&&*/
			v.Scrapped			== false				{
			
					v.Colour = new_value
	} else {
	
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("UPDATE_COLOUR: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 update_make
//=================================================================================================================================
func (t *SimpleChaincode) update_make(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, new_value string) ([]byte, error) {
	
	if 		v.Status			== STATE_MANUFACTURE	&&
			v.Owner				== caller				&& 
			caller_affiliation	== MANUFACTURER			&&
			v.Scrapped			== false				{
			
					v.Make = new_value
	} else {
	
															return nil, errors.New("Permission denied")
	
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("UPDATE_MAKE: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 update_model
//=================================================================================================================================
func (t *SimpleChaincode) update_model(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int, new_value string) ([]byte, error) {
	
	if 		v.Status			== STATE_MANUFACTURE	&&
			v.Owner				== caller				&& 
			caller_affiliation	== MANUFACTURER			&&
			v.Scrapped			== false				{
			
					v.Model = new_value
					
	} else {
															return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("UPDATE_MODEL: Error saving changes: %s", err); return nil, errors.New("Error saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 scrap_vehicle
//=================================================================================================================================
func (t *SimpleChaincode) scrap_vehicle(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int) ([]byte, error) {

	if		v.Status			== STATE_BEING_SCRAPPED	&& 
			v.Owner				== caller				&& 
			caller_affiliation	== SCRAP_MERCHANT		&& 
			v.Scrapped			== false				{
		
					v.Scrapped = true
				
	} else {
		return nil, errors.New("Permission denied")
	}
	
	_, err := t.save_changes(stub, v)
	
															if err != nil { fmt.Printf("SCRAP_VEHICLE: Error saving changes: %s", err); return nil, errors.New("SCRAP_VEHICLError saving changes") }
	
	return nil, nil
	
}

//=================================================================================================================================
//	 Read Functions
//=================================================================================================================================
//	 get_vehicle_details
//=================================================================================================================================
func (t *SimpleChaincode) get_vehicle_details(stub *shim.ChaincodeStub, c Vehicle, caller string, caller_affiliation int) ([]byte, error) {
	
	bytes, err := json.Marshal(v)
	
																if err != nil { return nil, errors.New("GET_VEHICLE_DETAILS: Invalid vehicle object") }
																
	if 		v.Owner				== caller		||
			caller_affiliation	== AUTHORITY	{
			
					return bytes, nil		
	} else {
																return nil, errors.New("Permission Denied")	
	}

}

//=================================================================================================================================
//	 get_vehicle_details
//=================================================================================================================================

func (t *SimpleChaincode) get_vehicles(stub *shim.ChaincodeStub, caller string, caller_affiliation int) ([]byte, error) {

	bytes, err := stub.GetState("v5cIDs")
		
																			if err != nil { return nil, errors.New("Unable to get v5cIDs") }
																	
	var v5cIDs V5C_Holder
	
	err = json.Unmarshal(bytes, &v5cIDs)						
	
																			if err != nil {	return nil, errors.New("Corrupt V5C_Holder") }
	
	result := "["
	
	var temp []byte
	var c Vehicle
	
	for _, v5c := range v5cIDs.V5Cs {
		
		v, err = t.retrieve_v5c(stub, v5c)
		
		if err != nil {return nil, errors.New("Failed to retrieve V5C")}
		
		temp, err = t.get_vehicle_details(stub, c, caller, caller_affiliation)
		
		if err == nil {
			result += string(temp) + ","	
		}
	}
	
	if len(result) == 1 {
		result = "[]"
	} else {
		result = result[:len(result)-1] + "]"
	}
	
	return []byte(result), nil
}

//=================================================================================================================================
//	 Main - main - Starts up the chaincode
//=================================================================================================================================
func main() {

	err := shim.Start(new(SimpleChaincode))
	
															if err != nil { fmt.Printf("Error starting Chaincode: %s", err) }
}
