/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
*   Endre Kulcsar - initial implementation and initial documentation
******************************************************************************/
//
//  File:               SNMPmsg_Oi.cc
//  Description:        SNMP protocol module external functions for OBJIDs
//  Rev:                R2B
//  Prodnr:             CNL 113 774
//

#include "SNMP_Functions.hh"
#if ! ( defined TTCN3_VERSION_MONOTONE ) || ( TTCN3_VERSION_MONOTONE <= 1100099)
typedef int my_objid_element;
#else
typedef OBJID::objid_element my_objid_element;
#endif
namespace SNMP__Functions{

OBJID oi__concat (const OBJID& first, const OBJID& second) {
	
	my_objid_element* cat_array = new my_objid_element[first.lengthof() + second.lengthof()];

	for (int i=0; i<first.lengthof(); i++) {
		cat_array[i] = first[i];
	}
	for (int i=0; i<second.lengthof(); i++) {
		cat_array[first.lengthof() + i] = second[i];
	}
	
	OBJID output = OBJID(first.lengthof() + second.lengthof(), (const my_objid_element*) cat_array);
	
	delete [] cat_array;
	
	return output;
};

INTEGER oi__size(const OBJID& input) {
	return INTEGER(input.lengthof());
}

BOOLEAN oi__eq (const OBJID& a, const OBJID& b) {
	return BOOLEAN(a == b);
}

OBJID oi__sub(const INTEGER& begin, const INTEGER& size, const OBJID& input) {
	if ((begin < 0) || (size < 0))
		TTCN_error("oi__sub(): Negative value for begin or size.");
	if ((int)begin + (int)size > input.lengthof())
		TTCN_error("oi__sub(): Sub-objid exceeds input.");

	return OBJID((int)size, (const my_objid_element*)input + (int)begin);
}

BOOLEAN oi__gt (const OBJID& a, const OBJID& b) {
	
	for (int i = 0; (i < a.lengthof()) && (i < b.lengthof()); i++)
		if (a[i] != b[i]) {
			return BOOLEAN(a[i] > b[i]);
		}
	return BOOLEAN(a.lengthof() > b.lengthof());
}

OBJID oi__addObjId (const OBJID& first, const SNMPmsg__Types::SetOfInteger& second) {
	
	my_objid_element* cat_array = new my_objid_element[first.lengthof() + second.size_of()];

	for (int i=0; i<first.lengthof(); i++) {
		cat_array[i] = first[i];
	}
	for (int i=0; i<second.size_of(); i++) {
		cat_array[first.lengthof() + i] = second[i].get_long_long_val();
	}
	
	OBJID output = OBJID(first.lengthof() + second.size_of(), (const my_objid_element*) cat_array);
	
	delete [] cat_array;
	
	return output;
};

OBJID oi__setvalue(const OBJID& input, const INTEGER& position, const INTEGER& val) {

	if (!input.is_bound()) TTCN_error("oi_setvalue(): unbound input");
	if (!position.is_bound()) TTCN_error("oi_setvalue(): unbound position");
	if (!val.is_bound()) TTCN_error("oi_setvalue(): unbound val");

	int int_position = position;
	my_objid_element int_val = val.get_long_long_val();

    if (int_position < 0) TTCN_error("oi_setvalue(): negative position");
    if (int_position > input.lengthof()) TTCN_error("oi_setvalue(): position greater than size");
    if (val < 0) TTCN_error("oi_setvalue(): negative value");

	OBJID output(input);
    output[int_position] = int_val;
	return output;
}

INTEGER oi__getvalue(const OBJID& input, const INTEGER& position) {

	if (!input.is_bound()) TTCN_error("oi_getvalue(): unbound input");
	if (!position.is_bound()) TTCN_error("oi_getvalue(): unbound position");

    int int_position = position;

    if (int_position < 0) TTCN_error("oi_getvalue(): negative position");
    if (int_position >= input.lengthof()) TTCN_error("oi_getvalue(): position greater than size");

    INTEGER ret_val;
    ret_val.set_long_long_val(input[int_position]);
    return ret_val;
}


TTCN_Module SNMP_Oi("SNMP_oi", __DATE__, __TIME__);
}
