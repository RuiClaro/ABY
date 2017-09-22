/**
 \file 		millionaire_prob.cpp
 \author 	sreeram.sadasivam@cased.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of the millionaire problem using ABY Framework.
 */

#include "bard_test.h"

int32_t test_bard_test_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {

	ofstream validation("validation_64_ADD.txt",ios::app);
	ofstream results("results_64_ADD.txt",ios::app);

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
		mt_alg);

	int role_id = role;
		
	for (int i = (-pow(2,63)+1); i < pow(2,63); i+=100000000000000003)
	//for (int i = 244; i <= 244; i +=100)
	{
		//A->244;B->-8999
	//	for (int j = -8999; j <= -8999; j +=100)
		for (int j = (-pow(2,63)+1); j < pow(2,63); j+=100000000000000001)
		{
			
			int64_t a = i;
			int64_t b = j;

			if(a+b >= pow(2,63) || a+b <= -pow(2,63)){
				/*cout << "a=" << a << "\n";
				cout << "b=" << b << "\n";*/
				continue;
			}
			//cout << "\n" << role;
			if(role_id == 0) {
			//cout << "\nprinting to results&validation files.\n";
			//cout << int(a) << "\n";
			//cout << int(b) << "\n";
			//cout << int(a+b) << "\n";
			validation << "A->" << int(a) << ";B->" << int(b) << endl;
			results << "A->" << int(a) << ";B->" << int(b) << endl;
			validation << "SUM->" << int(a+b) << endl;
			}

			


			/**
				Step 2: Get to know all the sharing types available in the program.
			*/

			vector<Sharing*>& sharings = party->GetSharings();

			/**
				Step 3: Create the circuit object on the basis of the sharing type
						being inputed.
			*/
			Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();


			/**
				Step 4: Creating the share objects - s_alice_money, s_bob_money which
						is used as input to the computation function. Also s_out
						which stores the output.
			*/

			share *s_alice_money, *s_bob_money, *s_out;

			/**
				Step 5: Initialize Alice's and Bob's money with random values.
						Both parties use the same seed, to be able to verify the
						result. In a real example each party would only supply
						one input value.
			*/

			uint64_t alice_money, bob_money, output;

		
			

			//cout << "\nBefore Computation\t";
			if (a < 0 ){
				alice_money = pow(2,64) + a;
				//cout << "\nAlice Money:\t" << alice_money;

			}else{
				alice_money = a;
			}
			if (b < 0 ){
				bob_money = pow(2,64) + b;
				//cout << "\nBob Money:\t" << bob_money;

			}else{
				bob_money = b;
			}

			/**
				Step 6: Copy the randomly generated money into the respective
						share objects using the circuit object method PutINGate()
						for my inputs and PutDummyINGate() for the other parties input.
						Also mention who is sharing the object.
			*/
			//s_alice_money = circ->PutINGate(alice_money, bitlen, CLIENT);
			//s_bob_money = circ->PutINGate(bob_money, bitlen, SERVER);
			if(role_id == 0) {
				s_alice_money = circ->PutDummyINGate(bitlen);
				s_bob_money = circ->PutINGate(bob_money, bitlen, SERVER);
			} else { //role == CLIENT
				s_alice_money = circ->PutINGate(alice_money, bitlen, CLIENT);
				s_bob_money = circ->PutDummyINGate(bitlen);
			}

			/**
				Step 7: Call the build method for building the circuit for the
						problem by passing the shared objects and circuit object.
						Don't forget to type cast the circuit object to type of share
			*/

			s_out = BuildBardTestCircuit(s_alice_money, s_bob_money,
					(BooleanCircuit*) circ);

			/**
				Step 8: Modify the output receiver based on the role played by
						the server and the client. This step writes the output to the
						shared output object based on the role.
			*/
			s_out = circ->PutOUTGate(s_out, ALL);
			
			/**
				Step 9: Executing the circuit using the ABYParty object evaluate the
						problem.
			*/
			party->ExecCircuit();

			/**
				Step 10:Type casting the value to 32 bit unsigned integer for output.
			*/
			
			output = s_out->get_clear_value<uint32_t>();
			int32_t outp;
			//cout << "\nOutput:\t" << output;
			if (output >= pow(2,63)){
				outp = (output - pow(2,64));
			}else{
				outp = output;
			}
		
			if(role_id == 0) {
				//cout << "printing to results file.\n";
				results << "SUM->" << int(outp) << endl;
			} 
			/*
			cout << "\nTesting Millionaire's Problem in " << get_sharing_name(sharing)
						<< " sharing: " << endl;
			cout << "\nAlice Money:\t" << alice_money;
			cout << "\nBob Money:\t" << bob_money;
			cout << "\nresult:\t" << outp;
			cout << "\n";
*/
			party->Reset();
		}
	}
	delete party;
	return 0;
}

share* BuildBardTestCircuit(share *s_alice, share *s_bob,
		BooleanCircuit *bc) {

	share* out;

	/** Calling the greater than equal function in the Boolean circuit class.*/
	out = bc->PutADDGate(s_alice, s_bob);

	return out;
}
