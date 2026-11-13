# Applies /work/pea.json (from fetch.py) to the Sure account "PEA BoursoBank":
# new/increased positions become Buy trades priced so Sure's cost basis = BoursoBank's PRU,
# decreases become Sells at the current price, and the cash balance is reconciled.
data = JSON.parse(File.read("/work/pea.json"))
if data["status"] == "not_configured" then puts "not configured yet"; exit 0 end
abort "fetch status: #{data['status']}" unless data["status"] == "ok"
acc = Account.find_by!(name: "PEA BoursoBank")
isin_map = { "FR0011871110" => "PUST", "FR0011871128" => "PSP5", "IE0002XZSHO1" => "WPEA" }

def ticker_for(isin, isin_map)
  return isin_map[isin] if isin_map[isin]
  res = Provider::Registry.get_provider(:yahoo_finance).search_securities(isin)
  sec = Array(res.data).find { |s| s.exchange_operating_mic == "XPAR" } || Array(res.data).first
  raise "no Yahoo match for #{isin}" unless sec
  sec.symbol.sub(/\.PA\z/, "")
end

holdings = acc.current_holdings.includes(:security).index_by { |h| h.security.ticker }
changed = false
ActiveRecord::Base.transaction do
  data["investments"].each do |inv|
    ticker = ticker_for(inv["isin"], isin_map)
    sec = Security.find_or_create_by!(ticker: ticker, exchange_operating_mic: "XPAR")
    sec.update_columns(offline: false, price_provider: "yahoo_finance", name: sec.name || inv["label"], country_code: "FR") if sec.offline? || sec.price_provider.blank?
    h = holdings[ticker]
    have_q, have_avg = (h&.qty || 0).to_d, (h&.avg_cost&.amount || 0).to_d
    want_q, pru = inv["qty"].to_d, inv["pru"].to_d
    diff = want_q - have_q
    next if diff.abs < 0.0001
    price = diff.positive? ? ((want_q * pru - have_q * have_avg) / diff) : inv["price"].to_d
    price = inv["price"].to_d if price <= 0
    price = price.round(4)
    Trade.create!(security: sec, qty: diff, price: price, currency: "EUR",
      investment_activity_label: diff.positive? ? "Buy" : "Sell",
      entry: Entry.new(account: acc, date: Date.current, amount: diff * price, currency: "EUR",
                       name: "#{diff.positive? ? 'Achat' : 'Vente'} #{inv['label']} (auto)"))
    puts "trade #{ticker} #{diff.to_f} @ #{price.to_f}"
    changed = true
  end
end
target_cash = data["cash"].to_d
if (acc.reload.cash_balance.to_d - target_cash).abs > 0.01 || changed
  holdings_value = data["investments"].sum { |i| i["valuation"].to_d }
  Account::CurrentBalanceManager.new(acc).set_current_balance(holdings_value + target_cash)
  puts "balance set: holdings #{holdings_value.to_f} + cash #{target_cash.to_f}"
end
acc.sync_later
puts "done; Bourso total=#{data['total']}"
