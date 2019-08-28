ruleset wovyn_base{
  meta {
    use module lab2_twilio alias twilio
    shares __testing
  }
  global {
    __testing = { "queries": [ { "name": "__testing" } ],
                  "events": [ { "domain": "wovyn", "type": "heartbeat",
                              "attrs": [ "temp", "baro" ] } ] }
    temperature_threshold = 75
    send_violation_phonenumber = 8017353755
    from_phonenumber = 8015152998
  }

  rule process_heartbeat {
    select when wovyn heartbeat where event:attr("genericThing") != null
    pre {
      genericThing = event:attr("genericThing").decode()
    }
    send_directive("GenericThing exists")
    fired {
      raise wovyn event "new_temperature_reading"
        attributes {"temperature": genericThing{"data"}{"temperature"}, "timestamp": time:now()}
    }
  }

  rule find_high_temps {
    select when wovyn new_temperature_reading
    pre {
      temperature = event:attr("temperature").decode()[0]{"temperatureF"}
    }
    if temperature > temperature_threshold then
      send_directive("Temperature above threshold")
    fired {
      raise wovyn event "threshold_violation"
        attributes {"temperature": temperature}
    }
  }

  rule threshold_violation {
    select when wovyn threshold_violation
    pre {
      temperature = event:attr("temperature")
    }
    twilio:sendMessage(send_violation_phonenumber, from_phonenumber,
        ("Temperature Violation: The temperature exceeds " + temperature_threshold + ". Temperature is " + temperature + " degrees Farenheit."))
  }

}
