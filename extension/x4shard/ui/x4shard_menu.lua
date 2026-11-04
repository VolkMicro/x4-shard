-- X4 Shard: "Connect by address", a small window where the player types (or pastes) a server's address, or a
-- private server's invite link. ui/x4shard_net.lua opens it when the player picks that choice in the ship
-- computer's server list; the text goes back through X4Shard.joinAddress (or X4Shard.cancelAddress).
-- Built like the game's own UserQuestionMenu.

-- a second copy of the extension loads in the same moment (see x4shard_net.lua): it stays idle
local loadedAt = getElapsedTime and getElapsedTime() or 0
if X4ShardMenuLoadedAt and math.abs(loadedAt - X4ShardMenuLoadedAt) < 2 then
	return
end
X4ShardMenuLoadedAt = loadedAt

local menu = {
	name = "X4ShardAddressMenu",
	text = "",
}

local config = {
	width = 560,
	layer = 2,
}

X4ShardMenu = {
	-- text: what the box shows at first (the address joined last time)
	open = function (text)
		menu.text = text or ""
		OpenMenu(menu.name, { 0, 0 }, nil)
	end,
}

local function init()
	Menus = Menus or {}
	table.insert(Menus, menu)
	if Helper then
		Helper.registerMenu(menu)
	end
end

function menu.cleanup()
	menu.frame = nil
	menu.editBox = nil
end

function menu.onShowMenu()
	Helper.clearDataForRefresh(menu, config.layer)
	local width = Helper.scaleX(config.width)
	menu.frame = Helper.createFrameHandle(menu, {
		standardButtons = {},
		width = width + 6 * Helper.borderSize,
		x = (Helper.viewWidth - width) / 2,
		y = Helper.viewHeight / 2,
		layer = config.layer,
		startAnimation = false,
	})
	menu.frame:setBackground("solid", { color = Color["frame_background_semitransparent"] })

	local ftable = menu.frame:addTable(2, { tabOrder = 1, borderEnabled = true, width = width, x = 3 * Helper.borderSize,
		y = 3 * Helper.borderSize, defaultInteractiveObject = true })
	local row = ftable:addRow(false, { fixed = true })
	row[1]:setColSpan(2):createText("X4 Shard: connect by address", Helper.headerRowCenteredProperties)
	row = ftable:addRow(false, { fixed = true })
	row[1]:setColSpan(2):createText("A server's address, like 203.0.113.5:47110, or a private server's invite link, "
		.. "like x4shard://203.0.113.5:47110/code. Type it or paste it with Ctrl+V, then Enter.", { wordwrap = true })
	row = ftable:addRow(true, { fixed = true })
	menu.editBox = row[1]:setColSpan(2):createEditBox({ height = Helper.standardButtonHeight, description = "Server address",
		maxChars = 200 }):setText(menu.text, {})
	row[1].handlers.onTextChanged = function (_, text) menu.text = text end
	row[1].handlers.onEditBoxDeactivated = function (_, text, _, isconfirmed)
		menu.text = text
		if isconfirmed then
			menu.connect()
		end
	end
	row = ftable:addRow(true, { fixed = true })
	row[1]:createButton({}):setText("Connect", { halign = "center" })
	row[1].handlers.onClick = menu.connect
	row[2]:createButton({}):setText("Cancel", { halign = "center" })
	row[2].handlers.onClick = function () return menu.onCloseElement("back") end

	menu.frame.properties.height = ftable.properties.y + ftable:getVisibleHeight() + 3 * Helper.borderSize
	-- below the middle: the game's own hints sit just above it
	menu.frame.properties.y = math.floor(Helper.viewHeight * 0.58)
	menu.frame:display()
	menu.activate = true
end

function menu.connect()
	local text = menu.text or ""
	Helper.closeMenu(menu, "close")
	menu.cleanup()
	if X4Shard and X4Shard.joinAddress then
		X4Shard.joinAddress(text)
	end
end

function menu.viewCreated(layer, ...)
end

menu.updateInterval = 0.1

function menu.onUpdate()
	if menu.activate and menu.editBox then
		menu.activate = nil
		ActivateEditBox(menu.editBox.id)
	end
	if menu.frame then
		menu.frame:update()
	end
end

function menu.onRowChanged(row, rowdata, uitable)
end

function menu.onSelectElement(uitable, modified, row)
end

function menu.onCloseElement(dueToClose)
	Helper.closeMenu(menu, dueToClose)
	menu.cleanup()
	if X4Shard and X4Shard.cancelAddress then
		X4Shard.cancelAddress()
	end
end

init()
