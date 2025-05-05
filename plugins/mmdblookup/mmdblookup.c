/* mmdblookup.c
 * Parse ipaddress field of the message into structured data using
 * MaxMindDB.
 *
 * Copyright 2013 Rao Chenlin.
 * Copyright 2017 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "parserif.h"

#include "maxminddb.h"

#define JSON_IPLOOKUP_NAME "!iplocation"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmdblookup")


DEF_OMOD_STATIC_DATA

/* config variables */
typedef struct _instanceData {
	char *pszKey;
	char *pszMmdbFile;
	struct {
		int     nmemb;
		char **name;
		char **varname;
	} fieldList;
	sbool reloadOnHup;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	MMDB_s        mmdb;
	pthread_mutex_t mmdbMutex;
	sbool mmdb_is_open;
} wrkrInstanceData_t;

struct modConfData_s {
	/* our overall config object */
	rsconf_t *pConf;
	const char *container;
};

/* modConf ptr to use for the current load process */
static modConfData_t *loadModConf = NULL;
/* modConf ptr to use for the current exec process */
static modConfData_t *runModConf  = NULL;


/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "container", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

/* tables for interfacing with the v6 config system
 * action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "key",      eCmdHdlrGetWord, CNFPARAM_REQUIRED },
	{ "mmdbfile", eCmdHdlrGetWord, CNFPARAM_REQUIRED },
	{ "fields",   eCmdHdlrArray,   CNFPARAM_REQUIRED },
	{ "reloadonhup", eCmdHdlrBinary, 0 },
};
static struct cnfparamblk actpblk = {
	CNFPARAMBLK_VERSION,
	sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	actpdescr
};


/* protype functions */
int open_mmdb(const char *file, MMDB_s *mmdb);
void close_mmdb(MMDB_s *mmdb);
int mmdb_get_value(
	MMDB_entry_s *const start,
	MMDB_entry_data_s *const entry_data,
	char *field
);
struct json_object *mmdb_entry_to_json(const MMDB_entry_data_s *entry);

int open_mmdb(const char *file, MMDB_s *mmdb) {
	int status = MMDB_open(file, MMDB_MODE_MMAP, mmdb);
	if (MMDB_SUCCESS != status) {
		dbgprintf("Can't open %s - %s\n", file, MMDB_strerror(status));
		if (MMDB_IO_ERROR == status) {
			dbgprintf("  IO error: %s\n", strerror(errno));
		}
		LogError(0, RS_RET_SUSPENDED, "maxminddb error: cannot open database file");
		return RS_RET_SUSPENDED;
	}

	return RS_RET_OK;
}

void close_mmdb(MMDB_s *mmdb) {
	MMDB_close(mmdb);
}

const char *SEP = "!";
#define MAX_PATH_ELEMENTS 7

// This is a thin wrapper function for MMDB_aget_value that knows how to convert
// the rsyslog field into MMDB path, e.g., "!continent!code" -> ["continent", "code"].
int mmdb_get_value(
	MMDB_entry_s *const start,
	MMDB_entry_data_s *const entry_data,
	char *field
) {
	const char **path = calloc(MAX_PATH_ELEMENTS + 1, sizeof(const char *));
	if (NULL == path) {
		return MMDB_OUT_OF_MEMORY_ERROR;
	}

	// Split the field into path elements to construct a path array.
	int i = 0;
	char *brkf;
	char *path_elem = strtok_r(field, SEP, &brkf);
	while (NULL != path_elem && i < MAX_PATH_ELEMENTS) {
		path[i] = path_elem;
		i++;
		path_elem = strtok_r(NULL, SEP, &brkf);
	}
	path[i] = NULL;

	int status = MMDB_aget_value(start, entry_data, path);

	free(path);

	return status;
}

// Helper function to convert MMDB_entry_data_s to json_object.
struct json_object *mmdb_entry_to_json(const MMDB_entry_data_s *entry) {
	if (!entry || entry->offset == 0) {
		return NULL;
	}

	switch (entry->type) {
	case MMDB_DATA_TYPE_UTF8_STRING:
		return json_object_new_string_len(entry->utf8_string, entry->data_size);
	case MMDB_DATA_TYPE_BYTES:
		char *hex_string = calloc((entry->data_size * 2) + 1, sizeof(char));
		if (NULL == hex_string) {
			dbgprintf("Error converting MMDB bytes to hex string\n");
			return NULL;
		}

		for (uint32_t i = 0; i < entry->data_size; i++) {
			sprintf(hex_string + (2 * i), "%02X", entry->bytes[i]);
		}

		struct json_object *json_string = json_object_new_string_len(
			hex_string,
			entry->data_size * 2
		);
		free(hex_string);

		return json_string;
	case MMDB_DATA_TYPE_DOUBLE:
		return json_object_new_double(entry->double_value);
	case MMDB_DATA_TYPE_FLOAT:
		return json_object_new_double((double)entry->float_value);
	case MMDB_DATA_TYPE_BOOLEAN:
		return json_object_new_boolean(entry->boolean);
	case MMDB_DATA_TYPE_UINT16:
		return json_object_new_int((int)entry->uint16);
	case MMDB_DATA_TYPE_UINT32:
		return json_object_new_int((int)entry->uint32);
	case MMDB_DATA_TYPE_INT32:
		return json_object_new_int(entry->int32);
	case MMDB_DATA_TYPE_UINT64:
		return json_object_new_int64((int64_t)entry->uint64);
	case MMDB_DATA_TYPE_UINT128: {
		// json-c doesn't have a direct 128-bit integer type.
		// Representing it as a string might be the best approach for lossless conversion.
		char buffer[40];
		snprintf(
			buffer,
			sizeof(buffer),
			"%llu%016llu",
			(unsigned long long)(entry->uint128 >> 64),
			(unsigned long long)(entry->uint128 & 0xFFFFFFFFFFFFFFFFULL)
		);
		return json_object_new_string(buffer);
	}
	case MMDB_DATA_TYPE_ARRAY: {
		json_object *json_array = json_object_new_array();
		MMDB_entry_data_list_s *list = entry;
		while (list) {
			json_object_array_add(
				json_array,
				mmdb_entry_to_json(&list->entry_data)
			);
			list = list->next;
		}
		return json_array;
	}
	case MMDB_DATA_TYPE_MAP: {
		struct json_object *json_map_obj = json_object_new_object();
		MMDB_entry_data_list_s *list = entry;
		while (list) {
			// The key in a map is always a UTF-8 string.
			if (MMDB_DATA_TYPE_UTF8_STRING == list->entry_data.type) {
				MMDB_entry_data_list_s *value_list = list->next;
				if (value_list) {
					json_object_object_add(
						json_map_obj,
						list->entry_data.utf8_string,
						mmdb_entry_to_json(&value_list->entry_data));
					list = value_list->next;
				} else {
					dbgprintf("MMDB map key without a value\n");
					list = NULL;
				}
			} else {
				dbgprintf("Non-string key in MMDB map\n");
				list = list->next;
			}
		}
		return json_map_obj;
	}
	default:
		dbgprintf("Unknown MMDB data type %d\n", entry->type);
		return NULL;
	}
}

static rsRetVal wrkr_reopen_mmdb(wrkrInstanceData_t *pWrkrData) {
	DEFiRet;
	pthread_mutex_lock(&pWrkrData->mmdbMutex);
	LogMsg(0, NO_ERRCODE, LOG_INFO, "mmdblookup: reopening MMDB file");
	if (pWrkrData->mmdb_is_open) close_mmdb(&pWrkrData->mmdb);
	pWrkrData->mmdb_is_open = 0;
	CHKiRet(open_mmdb(pWrkrData->pData->pszMmdbFile, &pWrkrData->mmdb));
	pWrkrData->mmdb_is_open = 1;

finalize_it:
	pthread_mutex_unlock(&pWrkrData->mmdbMutex);
	RETiRet;
}

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
	free((void*)runModConf->container);
ENDfreeCnf


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
	CHKiRet(open_mmdb(pData->pszMmdbFile, &pWrkrData->mmdb));
	pWrkrData->mmdb_is_open = 1;
	CHKiConcCtrl(pthread_mutex_init(&pWrkrData->mmdbMutex, NULL));
finalize_it:
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
	if(pData->fieldList.name != NULL) {
		for(int i = 0 ; i < pData->fieldList.nmemb ; ++i) {
			free(pData->fieldList.name[i]);
			free(pData->fieldList.varname[i]);
		}
		free(pData->fieldList.name);
		free(pData->fieldList.varname);
	}
	free(pData->pszKey);
	free(pData->pszMmdbFile);
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	if (pWrkrData->mmdb_is_open) close_mmdb(&pWrkrData->mmdb);
	pWrkrData->mmdb_is_open = 0;
	pthread_mutex_destroy(&pWrkrData->mmdbMutex);
ENDfreeWrkrInstance


BEGINsetModCnf
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTsetModCnf
	loadModConf->container = NULL;
	pvals = nvlstGetParams(lst, &modpblk, NULL);
	if(pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "mmdblookup: error processing module "
						"config parameters missing [module(...)]");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("module (global) param blk for mmdblookup:\n");
		cnfparamsPrint(&modpblk, pvals);
	}

	for(i = 0 ; i < modpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, "container")) {
			loadModConf->container = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("mmdblookup: program error, non-handled "
					  "param '%s' in setModCnf\n", modpblk.descr[i].name);
		}
	}

	if(loadModConf->container == NULL) {
		CHKmalloc(loadModConf->container = strdup(JSON_IPLOOKUP_NAME));
	}

finalize_it:
	if(pvals != NULL)
		cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->pszKey = NULL;
	pData->pszMmdbFile = NULL;
	pData->fieldList.nmemb = 0;
	pData->reloadOnHup = 1;
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	dbgprintf("newActInst (mmdblookup)\n");
	if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	for (i = 0; i < actpblk.nParams; ++i) {
		if (!pvals[i].bUsed)
			continue;
		if (!strcmp(actpblk.descr[i].name, "key")) {
			pData->pszKey = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "mmdbfile")) {
			pData->pszMmdbFile = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "fields")) {
			pData->fieldList.nmemb = pvals[i].val.d.ar->nmemb;
			CHKmalloc(pData->fieldList.name = calloc(pData->fieldList.nmemb, sizeof(char *)));
			CHKmalloc(pData->fieldList.varname = calloc(pData->fieldList.nmemb, sizeof(char *)));
			for (int j = 0; j <  pvals[i].val.d.ar->nmemb; ++j) {
				char *const param = es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
				char *varname = NULL;
				char *name;
				if(*param == ':') {
					char *b = strchr(param+1, ':');
					if(b == NULL) {
						parser_errmsg("mmdblookup: missing closing colon: '%s'", param);
						ABORT_FINALIZE(RS_RET_ERR);
					}
					*b = '\0'; /* split name & varname */
					varname = param+1;
					name = b+1;
				} else {
					name = param;
				}
				if(*name == '!')
					++name;
				CHKmalloc(pData->fieldList.name[j] = strdup(name));
				char vnamebuf[1024];
				snprintf(vnamebuf, sizeof(vnamebuf),
					"%s!%s", loadModConf->container,
					(varname == NULL) ? name : varname);
				CHKmalloc(pData->fieldList.varname[j] = strdup(vnamebuf));
				free(param);
			}
		} else if(!strcmp(actpblk.descr[i].name, "reloadonhup")) {
			pData->reloadOnHup = pvals[i].val.d.n;
		} else {
			dbgprintf("mmdblookup: program error, non-handled"
				" param '%s'\n", actpblk.descr[i].name);
		}
	}

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
	iRet = wrkr_reopen_mmdb(pWrkrData);
ENDtryResume


BEGINdoAction_NoStrings
	smsg_t **ppMsg = (smsg_t **) pMsgData;
	smsg_t *pMsg   = ppMsg[0];
	struct json_object *keyjson = NULL;
	const char *pszValue;
	instanceData *const pData = pWrkrData->pData;
CODESTARTdoAction
	/* ensure file is open before beginning */
	if (!pWrkrData->mmdb_is_open) {
		CHKiRet(wrkr_reopen_mmdb(pWrkrData));
	}

	/* key is given, so get the property json */
	msgPropDescr_t pProp;
	msgPropDescrFill(&pProp, (uchar*)pData->pszKey, strlen(pData->pszKey));
	rsRetVal localRet = msgGetJSONPropJSON(pMsg, &pProp, &keyjson);
	msgPropDescrDestruct(&pProp);

	pthread_mutex_lock(&pWrkrData->mmdbMutex);
	if (localRet != RS_RET_OK) {
		/* key not found in the message. nothing to do */
		ABORT_FINALIZE(RS_RET_OK);
	}
	/* key found, so get the value */
	pszValue = (char*)json_object_get_string(keyjson);
	if(pszValue == NULL) { /* json null object returns NULL! */
		pszValue = "";
	}

	int gai_err, mmdb_err;
	MMDB_lookup_result_s result = MMDB_lookup_string(&pWrkrData->mmdb, pszValue, &gai_err, &mmdb_err);

	if (0 != gai_err) {
		dbgprintf("Error from call to getaddrinfo for %s - %s\n", pszValue, gai_strerror(gai_err));
		ABORT_FINALIZE(RS_RET_OK);
	}
	if (MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR == mmdb_err) {
		LogMsg(0, NO_ERRCODE, LOG_INFO, "mmdblookup: Tried to search for an IPv6 address in an IPv4-only DB"
		", ignoring");
		ABORT_FINALIZE(RS_RET_OK);
	}
	if (MMDB_SUCCESS != mmdb_err) {
		dbgprintf("Got an error from the maxminddb library: %s\n", MMDB_strerror(mmdb_err));
		close_mmdb(&pWrkrData->mmdb);
		pWrkrData->mmdb_is_open = 0;
		ABORT_FINALIZE(RS_RET_IO_ERROR);
	}
	if (!result.found_entry) {
		dbgprintf("No entry found in database for '%s'\n", pszValue);
		ABORT_FINALIZE(RS_RET_OK);
	}

	const size_t max_field_len = 255;
	MMDB_entry_data_s entry_data;
	// Extract and amend fields (to message) as configured.
	//
	// For example, if the field is "!continent!code", we will get {"continent": {"code": "AS"}}.
	// Another example is "location" which implies getting the whole location object:
	// {"location": {"accuracy_radius": 50, "latitude": 34.772500, "longitude": 113.726600}.
	for (int i = 0; i < pData->fieldList.nmemb; ++i) {
		size_t field_len = strnlen((char *)(pData->fieldList.name[i]), max_field_len);
		char field[field_len + 1];
		strncpy(field, (char *)pData->fieldList.name[i], sizeof(field));
		field[field_len] = '\0'; // Ensure null termination.

		mmdb_err = mmdb_get_value(&result.entry, &entry_data, field);
		if (MMDB_SUCCESS != mmdb_err) {
			dbgprintf("Got an error looking up the entry data - %s\n", MMDB_strerror(mmdb_err));
			ABORT_FINALIZE(RS_RET_OK);
		}
		if (!entry_data.has_data || entry_data.offset <= 0) {
			continue;
		}

		struct json_object *field_json = mmdb_entry_to_json(&entry_data);
		if (NULL == field_json) {
			continue;
		}

		// field_json now contains the geoip field, so set it to the message.
		msgAddJSON(pMsg, (uchar *)pData->fieldList.varname[i], field_json, 0, 0);
		json_object_put(field_json);
	}

finalize_it:
	pthread_mutex_unlock(&pWrkrData->mmdbMutex);
	json_object_put(keyjson);
ENDdoAction

// HUP handling for the worker...
BEGINdoHUPWrkr
CODESTARTdoHUPWrkr
	dbgprintf("mmdblookup: HUP received\n");
	if (pWrkrData->pData->reloadOnHup) {
		iRet = wrkr_reopen_mmdb(pWrkrData);
	}
ENDdoHUPWrkr


NO_LEGACY_CONF_parseSelectorAct


BEGINmodExit
CODESTARTmodExit
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_doHUPWrkr
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
	/* we only support the current interface specification */
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
	dbgprintf("mmdblookup: module compiled with rsyslog version %s.\n", VERSION);
ENDmodInit
